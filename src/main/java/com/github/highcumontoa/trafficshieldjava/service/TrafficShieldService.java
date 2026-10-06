package com.github.highcumontoa.trafficshieldjava.service;

import com.github.highcumontoa.trafficshieldjava.config.ShieldProperties;
import com.github.highcumontoa.trafficshieldjava.model.AllowlistException;
import com.github.highcumontoa.trafficshieldjava.model.DecisionReason;
import com.github.highcumontoa.trafficshieldjava.model.QuotaTier;
import com.github.highcumontoa.trafficshieldjava.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.model.RuleSet;
import com.github.highcumontoa.trafficshieldjava.model.RuleUpdateRequest;
import com.github.highcumontoa.trafficshieldjava.model.SecurityRule;
import com.github.highcumontoa.trafficshieldjava.model.ShieldDecision;
import com.github.highcumontoa.trafficshieldjava.model.ShieldRequest;
import com.github.highcumontoa.trafficshieldjava.model.ShieldStats;
import com.github.highcumontoa.trafficshieldjava.ratelimit.RateLimiter;
import com.github.highcumontoa.trafficshieldjava.security.AllowlistMatcher;
import com.github.highcumontoa.trafficshieldjava.security.DefaultRules;
import com.github.highcumontoa.trafficshieldjava.security.IllegalRuleException;
import com.github.highcumontoa.trafficshieldjava.security.SecurityInspector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * 流量防护编排服务：所有入口（HTTP 网关入口、JSON 检查入口）都经过此处，
 * 因此不同入口对同一请求特征必然得到一致且可解释的结论。
 *
 * <p>单次请求处理顺序：先安全检测，命中即拒绝（不消耗限流配额）；
 * 未命中再进行按来源/规则的限流计数；最后记录统计并返回结论。</p>
 *
 * <p>规则更新：先对整张新规则表完成全部校验与编译，再通过唯一的
 * {@link AtomicReference}&lt;{@link ActiveRules}&gt; 一次原子发布。处理请求时只读取一次
 * 该引用，安全规则、限流规则、版本号都来自同一个不可变对象，
 * 更新过程中不可能出现新旧规则混合判定；校验失败抛
 * {@link IllegalRuleException}，旧引用保持不变。</p>
 */
@Service
public class TrafficShieldService {

    private static final Logger log = LoggerFactory.getLogger(TrafficShieldService.class);
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    private final ShieldProperties properties;
    private final SecurityInspector inspector = new SecurityInspector();
    private final RateLimiter rateLimiter;

    /** 当前生效规则及其编译结果，唯一的原子发布点。 */
    private final AtomicReference<ActiveRules> active = new AtomicReference<>();

    /** 统计：读锁用于判定期间自增，写锁用于快照与规则发布，保证字段间自洽。 */
    private final ReentrantReadWriteLock statsLock = new ReentrantReadWriteLock();
    private final AtomicLong total = new AtomicLong();
    private final AtomicLong allowed = new AtomicLong();
    private final AtomicLong rateLimitedCount = new AtomicLong();
    private final Map<DecisionReason, AtomicLong> securityCounters = new LinkedHashMap<>();

    public TrafficShieldService(ShieldProperties properties) {
        this.properties = properties;
        this.rateLimiter = new RateLimiter(properties.getMaxStateEntries());
        RuleSet initial = new RuleSet(
                DefaultRules.securityRules(),
                List.of(DefaultRules.defaultRateLimitRule(
                        properties.getDefaultLimit(), properties.getDefaultWindowSeconds())),
                List.of(),
                List.of(),
                1L);
        active.set(new ActiveRules(initial, inspector.compile(initial.securityRules())));
        for (DecisionReason r : List.of(DecisionReason.SQL_INJECTION, DecisionReason.XSS,
                DecisionReason.COMMAND_INJECTION, DecisionReason.PATH_TRAVERSAL,
                DecisionReason.SUSPICIOUS_ENCODING)) {
            securityCounters.put(r, new AtomicLong());
        }
    }

    /**
     * 对一次请求执行完整防护检查。
     *
     * <p>顺序：误拦例外匹配（只决定是否豁免签名规则）→ 安全检测 → 分级档位配额 →
     * 路径限流规则。被安全拒绝的请求不消耗任何限流配额；被档位限流的请求不再消耗
     * 路径规则配额。</p>
     */
    public ShieldDecision check(ShieldRequest request) {
        // 整个判定只取一次规则快照
        ActiveRules snapshot = active.get();
        long version = snapshot.set().version();

        statsLock.readLock().lock();
        try {
            total.incrementAndGet();

            ShieldDecision decision;
            if (properties.isEnabled()) {
                // 误拦例外：命中例外的请求跳过可配置签名规则，
                // 但内置的明显攻击编码检查（ENC-*）仍然执行，明显攻击不会被放过
                AllowlistException exemption = AllowlistMatcher.match(
                        snapshot.set().allowlistExceptions(), request.source(), request.path());
                SecurityInspector.Hit hit = inspector.inspect(
                        snapshot.compiledSecurity(), request, exemption != null);
                if (hit != null) {
                    decision = ShieldDecision.reject(hit.reason(), hit.ruleId(),
                            hit.detail(), version, request.source(), request.path());
                    securityCounters.get(hit.reason()).incrementAndGet();
                    logDecision(request, decision);
                    return decision;
                }
                if (exemption != null) {
                    log.info("误拦例外生效 | source={} path={} exception={}（仅豁免签名规则，"
                                    + "内置编码检查仍执行）",
                            request.source(), request.path(), exemption.id());
                }
            }

            // 来源分级配额：按档位表顺序取首个命中档，只按这一档计一次数
            QuotaTier tier = resolveTier(snapshot.set().quotaTiers(), request.source());
            if (tier != null) {
                RateLimiter.Denied tierDenied = rateLimiter.tryAcquireTier(
                        tier, request.source(), System.currentTimeMillis());
                if (tierDenied != null) {
                    decision = ShieldDecision.rateLimited(tierDenied.ruleId(),
                            tierDenied.retryAfterSeconds(), version,
                            request.source(), request.path());
                    rateLimitedCount.incrementAndGet();
                    logDecision(request, decision);
                    return decision;
                }
            }

            RateLimiter.Denied denied = rateLimiter.tryAcquire(snapshot.set().rateLimitRules(),
                    request.source(), request.path(), System.currentTimeMillis());
            if (denied != null) {
                decision = ShieldDecision.rateLimited(denied.ruleId(),
                        denied.retryAfterSeconds(), version, request.source(), request.path());
                rateLimitedCount.incrementAndGet();
                logDecision(request, decision);
                return decision;
            }

            decision = ShieldDecision.allow(version, request.source(), request.path());
            allowed.incrementAndGet();
            logDecision(request, decision);
            return decision;
        } finally {
            statsLock.readLock().unlock();
        }
    }

    /** 按档位表声明顺序解析来源命中的唯一档位；未命中任何档返回 null（不受分级配额约束）。 */
    private static QuotaTier resolveTier(List<QuotaTier> tiers, String source) {
        if (tiers == null || tiers.isEmpty()) {
            return null;
        }
        String src = source == null ? "" : source;
        for (QuotaTier t : tiers) {
            if (PATH_MATCHER.match(t.sourcePattern(), src)) {
                return t;
            }
        }
        return null;
    }

    private void logDecision(ShieldRequest req, ShieldDecision d) {
        log.info("防护判定 | source={} method={} path={} query={} headers={} bodyLen={} "
                        + "=> allowed={} reason={} rule={} retryAfter={} version={} | 依据: {}",
                req.source(), req.method(), req.path(), req.query(),
                req.headers(), req.body() == null ? 0 : req.body().length(),
                d.allowed(), d.reason(), d.ruleId(), d.retryAfterSeconds(),
                d.rulesVersion(), d.message());
    }

    /**
     * 原子更新规则。字段为 null 表示该部分保持不变；非 null 表示整表替换。
     * 新表中任何一条规则非法都会拒绝整个更新并保留旧规则。
     *
     * @return 更新后生效的规则版本
     */
    public long updateRules(RuleUpdateRequest request) {
        if (request == null) {
            throw new IllegalRuleException("更新请求不能为空");
        }
        ActiveRules current = active.get();

        List<SecurityRule> nextSecurity =
                request.securityRules() != null ? request.securityRules() : current.set().securityRules();
        List<RateLimitRule> nextRate =
                request.rateLimitRules() != null ? request.rateLimitRules() : current.set().rateLimitRules();
        List<QuotaTier> nextTiers =
                request.quotaTiers() != null ? request.quotaTiers() : current.set().quotaTiers();
        List<AllowlistException> nextExceptions =
                request.allowlistExceptions() != null
                        ? request.allowlistExceptions() : current.set().allowlistExceptions();

        // 先完整校验+编译，任何异常都在发布前抛出
        List<SecurityInspector.CompiledRule> compiled = inspector.compile(nextSecurity);
        validateRateRules(nextRate);
        validateQuotaTiers(nextTiers);
        validateAllowlistExceptions(nextExceptions);

        RuleSet nextSet = new RuleSet(List.copyOf(nextSecurity), List.copyOf(nextRate),
                List.copyOf(nextTiers), List.copyOf(nextExceptions),
                current.set().version() + 1);
        ActiveRules next = new ActiveRules(nextSet, compiled);

        // 唯一发布点
        statsLock.writeLock().lock();
        try {
            active.set(next);
        } finally {
            statsLock.writeLock().unlock();
        }
        log.info("规则已原子更新并生效: securityRules={} rateLimitRules={} quotaTiers={} "
                        + "allowlistExceptions={} version={}",
                nextSet.securityRules().size(), nextSet.rateLimitRules().size(),
                nextSet.quotaTiers().size(), nextSet.allowlistExceptions().size(),
                nextSet.version());
        return nextSet.version();
    }

    private static void validateQuotaTiers(List<QuotaTier> tiers) {
        if (tiers == null) {
            throw new IllegalRuleException("配额档位列表不能为 null（可传空列表表示不启用分级配额）");
        }
        Map<String, QuotaTier> seen = new LinkedHashMap<>();
        for (QuotaTier t : tiers) {
            if (t == null) {
                throw new IllegalRuleException("配额档位不能为 null");
            }
            if (t.id() == null || t.id().isBlank()) {
                throw new IllegalRuleException("配额档位 id 不能为空");
            }
            if (seen.containsKey(t.id())) {
                throw new IllegalRuleException("配额档位 id 重复: " + t.id());
            }
            if (t.sourcePattern() == null || t.sourcePattern().isBlank()) {
                throw new IllegalRuleException("配额档位 [" + t.id() + "] 的 sourcePattern 不能为空");
            }
            if (t.limit() <= 0) {
                throw new IllegalRuleException("配额档位 [" + t.id() + "] 的 limit 必须为正整数");
            }
            if (t.windowSeconds() <= 0) {
                throw new IllegalRuleException("配额档位 [" + t.id() + "] 的 windowSeconds 必须为正整数");
            }
            seen.put(t.id(), t);
        }
    }

    private static void validateAllowlistExceptions(List<AllowlistException> exceptions) {
        if (exceptions == null) {
            throw new IllegalRuleException("误拦例外列表不能为 null（可传空列表表示无例外）");
        }
        Map<String, AllowlistException> seen = new LinkedHashMap<>();
        for (AllowlistException e : exceptions) {
            if (e == null) {
                throw new IllegalRuleException("误拦例外不能为 null");
            }
            if (e.id() == null || e.id().isBlank()) {
                throw new IllegalRuleException("误拦例外 id 不能为空");
            }
            if (seen.containsKey(e.id())) {
                throw new IllegalRuleException("误拦例外 id 重复: " + e.id());
            }
            if (e.sourcePattern() == null || e.sourcePattern().isBlank()) {
                throw new IllegalRuleException("误拦例外 [" + e.id() + "] 的 sourcePattern 不能为空");
            }
            if (e.pathPattern() == null || e.pathPattern().isBlank()) {
                throw new IllegalRuleException("误拦例外 [" + e.id() + "] 的 pathPattern 不能为空");
            }
            seen.put(e.id(), e);
        }
    }

    private static void validateRateRules(List<RateLimitRule> rateRules) {
        if (rateRules == null || rateRules.isEmpty()) {
            throw new IllegalRuleException("限流规则列表不能为空");
        }
        Map<String, RateLimitRule> seen = new LinkedHashMap<>();
        for (RateLimitRule r : rateRules) {
            if (r == null) {
                throw new IllegalRuleException("限流规则不能为 null");
            }
            if (r.id() == null || r.id().isBlank()) {
                throw new IllegalRuleException("限流规则 id 不能为空");
            }
            if (seen.containsKey(r.id())) {
                throw new IllegalRuleException("限流规则 id 重复: " + r.id());
            }
            if (r.pathPattern() == null || r.pathPattern().isBlank()) {
                throw new IllegalRuleException("限流规则 [" + r.id() + "] 的 pathPattern 不能为空");
            }
            if (r.limit() <= 0) {
                throw new IllegalRuleException("限流规则 [" + r.id() + "] 的 limit 必须为正整数");
            }
            if (r.windowSeconds() <= 0) {
                throw new IllegalRuleException("限流规则 [" + r.id() + "] 的 windowSeconds 必须为正整数");
            }
            seen.put(r.id(), r);
        }
    }

    /**
     * 获取当前生效规则集（不可变）。
     */
    public RuleSet currentRules() {
        return active.get().set();
    }

    /**
     * 获取自洽的统计快照：在写锁下读取全部计数，满足
     * total = allowed + 各类安全拒绝之和 + 限流数。
     */
    public ShieldStats stats() {
        statsLock.writeLock().lock();
        try {
            RuleSet snapshot = active.get().set();
            Map<String, Long> byReason = new LinkedHashMap<>();
            for (Map.Entry<DecisionReason, AtomicLong> e : securityCounters.entrySet()) {
                byReason.put(e.getKey().name(), e.getValue().get());
            }
            return new ShieldStats(snapshot.version(), total.get(), allowed.get(),
                    Map.copyOf(byReason), rateLimitedCount.get());
        } finally {
            statsLock.writeLock().unlock();
        }
    }

    /**
     * 清理过期限流窗口（由调度任务调用）。
     */
    public void sweepWindows() {
        rateLimiter.sweepExpired(System.currentTimeMillis());
    }
}

package com.github.highcumontoa.trafficshieldjava.service;

import com.github.highcumontoa.trafficshieldjava.config.ShieldProperties;
import com.github.highcumontoa.trafficshieldjava.model.AllowlistException;
import com.github.highcumontoa.trafficshieldjava.model.DecisionReason;
import com.github.highcumontoa.trafficshieldjava.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.model.RuleSet;
import com.github.highcumontoa.trafficshieldjava.model.RuleUpdateRequest;
import com.github.highcumontoa.trafficshieldjava.model.SecurityRule;
import com.github.highcumontoa.trafficshieldjava.model.ShieldDecision;
import com.github.highcumontoa.trafficshieldjava.model.ShieldRequest;
import com.github.highcumontoa.trafficshieldjava.model.ShieldStats;
import com.github.highcumontoa.trafficshieldjava.model.SourceTierRule;
import com.github.highcumontoa.trafficshieldjava.ratelimit.RateLimiter;
import com.github.highcumontoa.trafficshieldjava.security.DefaultRules;
import com.github.highcumontoa.trafficshieldjava.security.IllegalRuleException;
import com.github.highcumontoa.trafficshieldjava.security.SecurityInspector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

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
 * <p>单次请求处理顺序：先安全检测（含误拦例外豁免），命中即拒绝（不消耗限流配额）；
 * 未命中再进行限流计数：配置了来源分级档位时按首个命中档位计一次数，
 * 未命中任何档位则回退普通限流规则；最后记录统计并返回结论。</p>
 *
 * <p>规则更新：安全规则、限流规则、分级档位、误拦例外四个部分先完成全部校验与编译，
 * 再通过唯一的 {@link AtomicReference}&lt;{@link ActiveRules}&gt; 一次原子发布。
 * 处理请求时只读取一次该引用，四部分规则与版本号都来自同一个不可变对象，
 * 更新过程中不可能出现新旧规则混合判定；任何一部分校验失败都抛
 * {@link IllegalRuleException}，整次更新被拒绝，旧引用保持不变。</p>
 */
@Service
public class TrafficShieldService {

    private static final Logger log = LoggerFactory.getLogger(TrafficShieldService.class);

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
                1L);
        active.set(new ActiveRules(initial, inspector.compile(initial.securityRules()),
                List.of()));
        for (DecisionReason r : List.of(DecisionReason.SQL_INJECTION, DecisionReason.XSS,
                DecisionReason.COMMAND_INJECTION, DecisionReason.PATH_TRAVERSAL,
                DecisionReason.SUSPICIOUS_ENCODING)) {
            securityCounters.put(r, new AtomicLong());
        }
    }

    /**
     * 对一次请求执行完整防护检查。
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
                SecurityInspector.Hit hit = inspector.inspect(snapshot.compiledSecurity(),
                        snapshot.compiledExceptions(), request);
                if (hit != null) {
                    decision = ShieldDecision.reject(hit.reason(), hit.ruleId(),
                            hit.detail(), version, request.source(), request.path());
                    securityCounters.get(hit.reason()).incrementAndGet();
                    logDecision(request, decision);
                    return decision;
                }
            }

            RateLimiter.Denied denied = rateLimiter.tryAcquire(snapshot.set().tierRules(),
                    snapshot.set().rateLimitRules(),
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
     * 四个部分（安全规则/限流规则/分级档位/误拦例外）中任何一条非法都会
     * 拒绝整个更新并保留旧规则。
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
        List<SourceTierRule> nextTiers =
                request.tierRules() != null ? request.tierRules() : current.set().tierRules();
        List<AllowlistException> nextExceptions =
                request.allowlistExceptions() != null
                        ? request.allowlistExceptions() : current.set().allowlistExceptions();

        // 先完整校验+编译，任何异常都在发布前抛出
        List<SecurityInspector.CompiledRule> compiled = inspector.compile(nextSecurity);
        validateRateRules(nextRate);
        validateTierRules(nextTiers);
        // 例外校验依赖同一次发布的安全规则表（豁免目标必须存在）
        List<SecurityInspector.CompiledException> compiledExceptions =
                inspector.compileExceptions(nextExceptions, nextSecurity);

        RuleSet nextSet = new RuleSet(List.copyOf(nextSecurity), List.copyOf(nextRate),
                List.copyOf(nextTiers), List.copyOf(nextExceptions),
                current.set().version() + 1);
        ActiveRules next = new ActiveRules(nextSet, compiled, compiledExceptions);

        // 唯一发布点
        statsLock.writeLock().lock();
        try {
            active.set(next);
        } finally {
            statsLock.writeLock().unlock();
        }
        log.info("规则已原子更新并生效: securityRules={} rateLimitRules={} tierRules={} "
                        + "allowlistExceptions={} version={}",
                nextSet.securityRules().size(), nextSet.rateLimitRules().size(),
                nextSet.tierRules().size(), nextSet.allowlistExceptions().size(),
                nextSet.version());
        return nextSet.version();
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

    private static void validateTierRules(List<SourceTierRule> tierRules) {
        if (tierRules == null || tierRules.isEmpty()) {
            return; // 空列表表示未启用分级，合法
        }
        Map<String, SourceTierRule> seen = new LinkedHashMap<>();
        for (SourceTierRule t : tierRules) {
            if (t == null) {
                throw new IllegalRuleException("分级档位不能为 null");
            }
            if (t.id() == null || t.id().isBlank()) {
                throw new IllegalRuleException("分级档位 id 不能为空");
            }
            if (seen.containsKey(t.id())) {
                throw new IllegalRuleException("分级档位 id 重复: " + t.id());
            }
            if (t.sourcePattern() == null || t.sourcePattern().isBlank()) {
                throw new IllegalRuleException("分级档位 [" + t.id() + "] 的 sourcePattern 不能为空");
            }
            if (t.pathPattern() == null || t.pathPattern().isBlank()) {
                throw new IllegalRuleException("分级档位 [" + t.id() + "] 的 pathPattern 不能为空");
            }
            if (t.limit() <= 0) {
                throw new IllegalRuleException("分级档位 [" + t.id() + "] 的 limit 必须为正整数");
            }
            if (t.windowSeconds() <= 0) {
                throw new IllegalRuleException("分级档位 [" + t.id() + "] 的 windowSeconds 必须为正整数");
            }
            seen.put(t.id(), t);
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
     * 清理过期窗口并执行状态容量回收（由调度任务调用；与正常判定并发安全）。
     */
    public void sweepWindows() {
        rateLimiter.sweepExpired(System.currentTimeMillis());
    }
}

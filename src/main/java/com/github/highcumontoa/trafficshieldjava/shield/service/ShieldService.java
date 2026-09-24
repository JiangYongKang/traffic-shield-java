package com.github.highcumontoa.trafficshieldjava.shield.service;

import com.github.highcumontoa.trafficshieldjava.shield.config.RuleValidator;
import com.github.highcumontoa.trafficshieldjava.shield.config.ShieldConfig;
import com.github.highcumontoa.trafficshieldjava.shield.model.Decision;
import com.github.highcumontoa.trafficshieldjava.shield.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.shield.model.RateLimitVerdict;
import com.github.highcumontoa.trafficshieldjava.shield.model.RejectReason;
import com.github.highcumontoa.trafficshieldjava.shield.model.RequestContext;
import com.github.highcumontoa.trafficshieldjava.shield.model.ShieldResult;
import com.github.highcumontoa.trafficshieldjava.shield.ratelimit.RateLimiter;
import com.github.highcumontoa.trafficshieldjava.shield.security.SecurityInspector;
import com.github.highcumontoa.trafficshieldjava.shield.security.SecurityInspector.SecurityHit;
import com.github.highcumontoa.trafficshieldjava.shield.stats.ShieldStats;
import com.github.highcumontoa.trafficshieldjava.shield.stats.StatsSnapshot;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 防护门面：在同一份配置快照上依次执行 安全检测 -&gt; 限流，并记录统计。
 *
 * <p>{@link #config} 为 {@code volatile} 引用，整体替换；check 开始时获取一次局部
 * 快照，安全规则与限流规则都来自该快照，更新期间绝不会出现新旧规则混合判定。</p>
 */
public class ShieldService {

    private static final Logger log = LoggerFactory.getLogger(ShieldService.class);

    private volatile ShieldConfig config;
    private final SecurityInspector inspector;
    private final RateLimiter rateLimiter;
    private final ShieldStats stats;

    public ShieldService(ShieldConfig initialConfig,
                         SecurityInspector inspector,
                         RateLimiter rateLimiter,
                         ShieldStats stats) {
        RuleValidator.validate(initialConfig);
        this.config = initialConfig;
        this.inspector = inspector;
        this.rateLimiter = rateLimiter;
        this.stats = stats;
    }

    public ShieldResult check(RequestContext request) {
        // 单次判定固定使用同一份配置快照
        ShieldConfig snapshot = this.config;

        // 1) 安全检测：命中即拒绝，并给出稳定可区分的规则与原因
        Optional<SecurityHit> hit = inspector.inspect(snapshot.securityRules(), request);
        if (hit.isPresent()) {
            SecurityHit h = hit.get();
            stats.recordRejected(h.rule().reason());
            log.info("[shield] 判定=拒绝(安全) source={} {} {} rule={} reason={} evidence={}",
                    request.source(), request.method(), request.path(),
                    h.rule().id(), h.rule().reason(), h.evidence());
            return new ShieldResult(Decision.REJECT_SECURITY,
                    h.rule().reason(), h.rule().id(), h.evidence(), 0L);
        }

        // 2) 限流：按入口匹配唯一规则，按来源计数
        RateLimitRule rule = matchRateRule(snapshot, request.path());
        if (rule != null) {
            RateLimitVerdict verdict =
                    rateLimiter.tryAcquire(rule, request.source(), System.currentTimeMillis());
            if (!verdict.allowed()) {
                stats.recordRateLimited();
                log.info("[shield] 判定=拒绝(限流) source={} {} {} rule={} count={}/{} retryAfterMs={}",
                        request.source(), request.method(), request.path(), rule.id(),
                        verdict.currentCount(), rule.limit(), verdict.retryAfterMillis());
                return new ShieldResult(Decision.REJECT_RATE_LIMIT,
                        RejectReason.RATE_LIMITED, rule.id(),
                        "count=" + verdict.currentCount() + "/" + rule.limit(),
                        verdict.retryAfterMillis());
            }
        }

        // 3) 放行
        stats.recordAllowed();
        log.info("[shield] 判定=放行 source={} {} {} rule={}",
                request.source(), request.method(), request.path(),
                rule == null ? "-" : rule.id());
        return new ShieldResult(Decision.ALLOW,
                null, rule == null ? null : rule.id(), null, 0L);
    }

    /**
     * 原子更新规则：先校验，非法则抛出异常且保留原规则；通过后在同一同步块内
     * 整体替换配置引用，后续 check 自然使用新快照；限流计数同步重置。
     */
    public synchronized void updateConfig(ShieldConfig newConfig) {
        RuleValidator.validate(newConfig);
        rateLimiter.reset();
        this.config = newConfig;
        log.info("[shield] 规则已原子更新: securityRules={}, rateLimitRules={}",
                newConfig.securityRules().size(), newConfig.rateLimitRules().size());
    }

    public ShieldConfig currentConfig() {
        return config;
    }

    public StatsSnapshot statsSnapshot() {
        return stats.snapshot();
    }

    private RateLimitRule matchRateRule(ShieldConfig snapshot, String path) {
        for (RateLimitRule rule : snapshot.rateLimitRules()) {
            if (rule.pathPattern().equals(path)) {
                return rule;
            }
        }
        return null;
    }
}

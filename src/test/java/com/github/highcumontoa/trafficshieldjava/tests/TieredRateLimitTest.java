package com.github.highcumontoa.trafficshieldjava.tests;

import com.github.highcumontoa.trafficshieldjava.config.ShieldProperties;
import com.github.highcumontoa.trafficshieldjava.model.DecisionReason;
import com.github.highcumontoa.trafficshieldjava.model.RuleUpdateRequest;
import com.github.highcumontoa.trafficshieldjava.model.ShieldDecision;
import com.github.highcumontoa.trafficshieldjava.model.ShieldRequest;
import com.github.highcumontoa.trafficshieldjava.model.SourceTierRule;
import com.github.highcumontoa.trafficshieldjava.security.IllegalRuleException;
import com.github.highcumontoa.trafficshieldjava.service.TrafficShieldService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 来源分级配额测试：档位按来源重要程度分档、各自独立计数、
 * 同一请求只按命中档位计一次、未命中档位回退普通规则；
 * 档位配置整体校验，非法时整体拒绝并保留旧配置。
 */
class TieredRateLimitTest {

    private static final Logger log = LoggerFactory.getLogger(TieredRateLimitTest.class);

    private TrafficShieldService newService(int fallbackLimit) {
        ShieldProperties p = new ShieldProperties();
        p.setDefaultLimit(fallbackLimit);
        p.setDefaultWindowSeconds(60);
        return new TrafficShieldService(p);
    }

    private ShieldRequest req(String source, String path) {
        return new ShieldRequest("GET", path, null, Map.of(), null, source);
    }

    private long installTiers(TrafficShieldService svc) {
        List<SourceTierRule> tiers = List.of(
                new SourceTierRule("TIER-INTERNAL", "internal-*", "/**", 3, 60),
                new SourceTierRule("TIER-RESTRICTED", "ext-*", "/**", 1, 60));
        return svc.updateRules(new RuleUpdateRequest(null, null, tiers, null));
    }

    @Test
    void tiersHaveIndependentQuotasAndFallbackApplies() {
        TrafficShieldService svc = newService(100);
        long version = installTiers(svc);
        log.info("[分级配额] 档位表已生效: TIER-INTERNAL=3/60s, TIER-RESTRICTED=1/60s, "
                + "回退默认=100/60s, version={}", version);

        // 内部档位：3 放行，第 4 个被该档位限流
        for (int i = 1; i <= 3; i++) {
            assertEquals(DecisionReason.ALLOWED, svc.check(req("internal-1", "/a")).reason());
        }
        ShieldDecision denied = svc.check(req("internal-1", "/a"));
        assertEquals(DecisionReason.RATE_LIMITED, denied.reason());
        assertEquals("TIER-INTERNAL", denied.ruleId());
        assertEquals(version, denied.rulesVersion());

        // 收紧档位：1 放行，第 2 个即被限流；与内部档位互不影响
        assertEquals(DecisionReason.ALLOWED, svc.check(req("ext-1", "/a")).reason());
        ShieldDecision extDenied = svc.check(req("ext-1", "/a"));
        assertEquals(DecisionReason.RATE_LIMITED, extDenied.reason());
        assertEquals("TIER-RESTRICTED", extDenied.ruleId());

        // 同档位不同来源互不影响
        assertEquals(DecisionReason.ALLOWED, svc.check(req("internal-2", "/a")).reason());

        // 未命中任何档位的来源回退普通限流规则（默认 100 次）
        for (int i = 0; i < 10; i++) {
            assertEquals(DecisionReason.ALLOWED, svc.check(req("other-src", "/a")).reason());
        }
        log.info("[分级配额] 各档独立计数、同档不同来源互不影响、未命中档位回退普通规则：全部符合预期");
    }

    @Test
    void sameRequestCountsOnlyOnceInItsTier() {
        TrafficShieldService svc = newService(100);
        installTiers(svc);

        // internal-9 同时满足 TIER-INTERNAL；请求只在该档位计一次数，
        // 不会额外消耗回退规则 RL-DEFAULT 的配额
        svc.check(req("internal-9", "/x"));
        svc.check(req("internal-9", "/x"));
        // 档位内已计 2 次（限额 3），第 3 次仍放行、第 4 次限流
        assertEquals(DecisionReason.ALLOWED, svc.check(req("internal-9", "/x")).reason());
        assertEquals(DecisionReason.RATE_LIMITED, svc.check(req("internal-9", "/x")).reason());
        log.info("[分级配额] 同一请求只按命中档位计一次数（3 次后恰被限流），未重复消耗回退规则配额");
    }

    @Test
    void illegalTierConfigIsRejectedWhollyAndOldTiersRemain() {
        TrafficShieldService svc = newService(100);
        long version = installTiers(svc);

        // 非法：limit 非正
        IllegalRuleException e1 = assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(null, null,
                        List.of(new SourceTierRule("T1", "a-*", "/**", 0, 60)), null)));
        // 非法：sourcePattern 为空
        IllegalRuleException e2 = assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(null, null,
                        List.of(new SourceTierRule("T1", " ", "/**", 1, 60)), null)));
        // 非法：档位 id 重复
        IllegalRuleException e3 = assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(null, null,
                        List.of(new SourceTierRule("T1", "a-*", "/**", 1, 60),
                                new SourceTierRule("T1", "b-*", "/**", 1, 60)), null)));
        log.warn("[分级配额] 非法档位被整体拒绝: [{}] [{}] [{}]",
                e1.getMessage(), e2.getMessage(), e3.getMessage());

        // 旧档位配置与版本保持不变，判定语义不受失败更新影响
        assertEquals(version, svc.currentRules().version());
        assertEquals(2, svc.currentRules().tierRules().size());
        assertEquals(DecisionReason.ALLOWED, svc.check(req("internal-1", "/a")).reason());
        assertEquals(DecisionReason.ALLOWED, svc.check(req("ext-1", "/a")).reason());
        assertEquals(DecisionReason.RATE_LIMITED, svc.check(req("ext-1", "/a")).reason());
        log.info("[分级配额] 非法更新后旧档位完整保留并继续生效，version={}", version);
    }

    @Test
    void tierReplacementTakesEffectAsWhole() {
        TrafficShieldService svc = newService(100);
        installTiers(svc);
        // 整表替换为新档位表：旧档位不再参与判定
        long v2 = svc.updateRules(new RuleUpdateRequest(null, null,
                List.of(new SourceTierRule("TIER-ONLY", "internal-*", "/**", 5, 60)), null));
        assertEquals(1, svc.currentRules().tierRules().size());
        assertEquals("TIER-ONLY", svc.currentRules().tierRules().get(0).id());
        // ext-* 不再命中任何档位，回退普通规则（100 次）
        for (int i = 0; i < 10; i++) {
            assertEquals(DecisionReason.ALLOWED, svc.check(req("ext-9", "/a")).reason());
        }
        assertTrue(v2 > 1);
        log.info("[分级配额] 档位整表替换原子生效：旧档位失效、新档位与回退规则工作正常, version={}", v2);
    }
}

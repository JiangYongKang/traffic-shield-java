package com.github.highcumontoa.trafficshieldjava.tests;

import com.github.highcumontoa.trafficshieldjava.config.ShieldProperties;
import com.github.highcumontoa.trafficshieldjava.model.DecisionReason;
import com.github.highcumontoa.trafficshieldjava.model.QuotaTier;
import com.github.highcumontoa.trafficshieldjava.model.RuleUpdateRequest;
import com.github.highcumontoa.trafficshieldjava.model.ShieldDecision;
import com.github.highcumontoa.trafficshieldjava.model.ShieldRequest;
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
 * 来源分级配额测试：档位独立计数、单请求只计一次、整体替换立即生效、非法配置整体拒绝。
 */
class TieredQuotaTest {

    private static final Logger log = LoggerFactory.getLogger(TieredQuotaTest.class);

    private TrafficShieldService newService() {
        ShieldProperties p = new ShieldProperties();
        p.setDefaultLimit(1_000_000); // 路径限流规则放开，只观察分级档位
        p.setDefaultWindowSeconds(60);
        return new TrafficShieldService(p);
    }

    private ShieldRequest req(String source) {
        return new ShieldRequest("GET", "/api/x", null, Map.of(), null, source);
    }

    private List<QuotaTier> threeTiers() {
        return List.of(
                new QuotaTier("TIER-INTERNAL", "internal-*", 3, 60),
                new QuotaTier("TIER-EXTERNAL", "ext-*", 2, 60),
                new QuotaTier("TIER-TIGHT", "tight-*", 1, 60));
    }

    @Test
    void tiersHaveIndependentQuotasAndSingleCounting() {
        TrafficShieldService svc = newService();
        svc.updateRules(new RuleUpdateRequest(null, null, threeTiers(), null));

        // 内部档：限额 3
        int internalAllowed = 0;
        for (int i = 0; i < 5; i++) {
            if (svc.check(req("internal-1")).allowed()) internalAllowed++;
        }
        // 外部档：限额 2
        int externalAllowed = 0;
        for (int i = 0; i < 5; i++) {
            if (svc.check(req("ext-1")).allowed()) externalAllowed++;
        }
        // 收紧档：限额 1
        int tightAllowed = 0;
        for (int i = 0; i < 5; i++) {
            if (svc.check(req("tight-1")).allowed()) tightAllowed++;
        }
        // 未命中任何档位的来源：不受分级配额约束
        int otherAllowed = 0;
        for (int i = 0; i < 10; i++) {
            if (svc.check(req("other-1")).allowed()) otherAllowed++;
        }

        log.info("[分级配额] 内部档放行={}/3 外部档放行={}/2 收紧档放行={}/1 未分级来源放行={}/10",
                internalAllowed, externalAllowed, tightAllowed, otherAllowed);
        assertEquals(3, internalAllowed, "内部档必须按自己的额度放行 3 次");
        assertEquals(2, externalAllowed, "外部档必须按自己的额度放行 2 次");
        assertEquals(1, tightAllowed, "收紧档必须按自己的额度放行 1 次");
        assertEquals(10, otherAllowed, "未命中档位的来源不受分级配额约束");

        ShieldDecision denied = svc.check(req("tight-1"));
        assertEquals(DecisionReason.RATE_LIMITED, denied.reason());
        assertEquals("TIER-TIGHT", denied.ruleId(), "拒绝必须归因到命中的档位");
        log.info("[分级配额] 收紧档超限结论: reason={} ruleId={} retryAfter={}s",
                denied.reason(), denied.ruleId(), denied.retryAfterSeconds());
    }

    @Test
    void firstMatchingTierCountsOncePerRequest() {
        TrafficShieldService svc = newService();
        // app-vip1 同时匹配 app-* 与 app-vip*，按声明顺序只命中 TIER-A（限额 2）
        svc.updateRules(new RuleUpdateRequest(null, null, List.of(
                new QuotaTier("TIER-A", "app-*", 2, 60),
                new QuotaTier("TIER-B", "app-vip*", 100, 60)), null));

        int allowed = 0;
        for (int i = 0; i < 4; i++) {
            ShieldDecision d = svc.check(req("app-vip1"));
            if (d.allowed()) allowed++;
        }
        ShieldDecision denied = svc.check(req("app-vip1"));
        log.info("[分级配额] 重叠档位首个命中生效: 放行={} 拒绝档位={}", allowed, denied.ruleId());
        assertEquals(2, allowed, "只按首个命中档（限额2）计一次数，不按 TIER-B 的 100 放行");
        assertEquals("TIER-A", denied.ruleId());
    }

    @Test
    void tierReplacementTakesEffectAtomically() {
        TrafficShieldService svc = newService();
        svc.updateRules(new RuleUpdateRequest(null, null, threeTiers(), null));
        long v1 = svc.currentRules().version();

        // 整表替换：内部档收紧为 1，外部档取消（不在新表中）
        svc.updateRules(new RuleUpdateRequest(null, null, List.of(
                new QuotaTier("TIER-INTERNAL", "internal-*", 1, 60)), null));
        long v2 = svc.currentRules().version();
        assertTrue(v2 > v1, "替换必须产生新版本");

        // 新档位立即生效：新来源第一个请求放行，第二个即被新档位限流
        ShieldDecision first = svc.check(req("internal-new"));
        ShieldDecision second = svc.check(req("internal-new"));
        assertTrue(first.allowed());
        assertEquals(DecisionReason.RATE_LIMITED, second.reason());
        assertEquals("TIER-INTERNAL", second.ruleId());
        assertEquals(v2, second.rulesVersion(), "判定必须使用新档位表的版本");

        // 被移出档位表的外部来源不再受分级配额约束
        int extAllowed = 0;
        for (int i = 0; i < 5; i++) {
            if (svc.check(req("ext-new")).allowed()) extAllowed++;
        }
        log.info("[分级配额] 档位整表替换: v{} -> v{}，内部档收紧立即生效，外部档移除后放行={}/5",
                v1, v2, extAllowed);
        assertEquals(5, extAllowed, "档位表整体替换后被移除的档位不再约束来源");
    }

    @Test
    void illegalTierConfigIsRejectedAndOldTiersRemain() {
        TrafficShieldService svc = newService();
        svc.updateRules(new RuleUpdateRequest(null, null, threeTiers(), null));
        long versionBefore = svc.currentRules().version();

        // 非法：limit 非正
        assertThrows(IllegalRuleException.class, () -> svc.updateRules(
                new RuleUpdateRequest(null, null, List.of(
                        new QuotaTier("BAD-1", "x-*", 0, 60)), null)));
        // 非法：windowSeconds 非正
        assertThrows(IllegalRuleException.class, () -> svc.updateRules(
                new RuleUpdateRequest(null, null, List.of(
                        new QuotaTier("BAD-2", "x-*", 5, -1)), null)));
        // 非法：id 为空
        assertThrows(IllegalRuleException.class, () -> svc.updateRules(
                new RuleUpdateRequest(null, null, List.of(
                        new QuotaTier(" ", "x-*", 5, 60)), null)));
        // 非法：id 重复（一条合法一条非法，整体拒绝）
        assertThrows(IllegalRuleException.class, () -> svc.updateRules(
                new RuleUpdateRequest(null, null, List.of(
                        new QuotaTier("DUP", "a-*", 5, 60),
                        new QuotaTier("DUP", "b-*", 5, 60)), null)));
        // 非法：sourcePattern 为空
        assertThrows(IllegalRuleException.class, () -> svc.updateRules(
                new RuleUpdateRequest(null, null, List.of(
                        new QuotaTier("BAD-3", "", 5, 60)), null)));

        assertEquals(versionBefore, svc.currentRules().version(),
                "非法档位配置必须整体拒绝，版本不变");
        assertEquals(3, svc.currentRules().quotaTiers().size(), "旧档位表必须保留");

        // 旧档位行为不变：新来源仍按旧档位限额 3 判定
        int allowed = 0;
        for (int i = 0; i < 5; i++) {
            if (svc.check(req("internal-keep")).allowed()) allowed++;
        }
        log.info("[分级配额] 非法配置整体拒绝后旧档位保留: version={} 内部档放行={}/3",
                versionBefore, allowed);
        assertEquals(3, allowed);
    }
}

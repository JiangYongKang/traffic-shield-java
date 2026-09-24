package com.github.highcumontoa.trafficshieldjava.tests;

import com.github.highcumontoa.trafficshieldjava.config.ShieldProperties;
import com.github.highcumontoa.trafficshieldjava.model.DecisionReason;
import com.github.highcumontoa.trafficshieldjava.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.model.RuleUpdateRequest;
import com.github.highcumontoa.trafficshieldjava.model.SecurityRule;
import com.github.highcumontoa.trafficshieldjava.model.ShieldDecision;
import com.github.highcumontoa.trafficshieldjava.model.ShieldRequest;
import com.github.highcumontoa.trafficshieldjava.model.ShieldStats;
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
 * 编排服务单测：规则原子更新、非法规则被拒且旧规则保留、统计自洽。
 */
class TrafficShieldServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TrafficShieldServiceTest.class);

    private TrafficShieldService newService(int limit, int windowSeconds) {
        ShieldProperties p = new ShieldProperties();
        p.setDefaultLimit(limit);
        p.setDefaultWindowSeconds(windowSeconds);
        return new TrafficShieldService(p);
    }

    private ShieldRequest req(String source, String path, String query) {
        return new ShieldRequest("GET", path, query, Map.of(), null, source);
    }

    @Test
    void illegalRuleUpdateIsRejectedAndOldRulesRemain() {
        TrafficShieldService svc = newService(5, 60);
        int before = svc.currentRules().securityRules().size();
        long versionBefore = svc.currentRules().version();

        // 非法类别
        SecurityRule badCategory = new SecurityRule("X", "x", "NOT_A_REASON", "abc");
        IllegalRuleException e = assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(List.of(badCategory), null)));
        log.warn("[规则更新] 非法类别被拒绝: {}", e.getMessage());

        // 非法正则
        SecurityRule badRegex = new SecurityRule("X", "x", "XSS", "[unterminated");
        assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(List.of(badRegex), null)));

        // 非法限流参数
        RateLimitRule badLimit = new RateLimitRule("RL", "/**", 0, 10);
        assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(null, List.of(badLimit))));

        // 旧规则数量与版本保持不变
        assertEquals(before, svc.currentRules().securityRules().size());
        assertEquals(versionBefore, svc.currentRules().version());
        log.info("[规则更新] 拒绝非法更新后，旧规则完整保留：{} 条，版本 {}",
                before, versionBefore);
    }

    @Test
    void validUpdateTakesEffectAtomically() {
        TrafficShieldService svc = newService(100, 60);
        SecurityRule custom = new SecurityRule("CUSTOM-001", "自定义禁词",
                DecisionReason.XSS.name(), "forbidden-token");
        long v = svc.updateRules(new RuleUpdateRequest(List.of(custom), null));
        assertEquals(2, v);
        assertEquals(1, svc.currentRules().securityRules().size());

        ShieldDecision hit = svc.check(req("s1", "/x", "q=forbidden-token"));
        assertEquals(DecisionReason.XSS, hit.reason());
        assertEquals("CUSTOM-001", hit.ruleId());
        assertEquals(v, hit.rulesVersion());

        // 旧默认规则已整体替换，不应再命中
        ShieldDecision old = svc.check(req("s2", "/x", "q=1%20or%201=1"));
        assertEquals(DecisionReason.ALLOWED, old.reason());
        log.info("[规则更新] 新规则原子生效：自定义命中、旧规则不再参与判定，version={}", v);
    }

    @Test
    void securityRejectDoesNotConsumeRateLimitQuota() {
        TrafficShieldService svc = newService(2, 60);
        // 3 个恶意请求全部安全拒绝
        for (int i = 0; i < 3; i++) {
            ShieldDecision d = svc.check(req("sec-src", "/p", "id=1%20or%201=1"));
            assertEquals(DecisionReason.SQL_INJECTION, d.reason());
        }
        // 配额未被安全拒绝消耗：正常请求仍应放行 2 个
        ShieldDecision a1 = svc.check(req("sec-src", "/p", "ok=1"));
        ShieldDecision a2 = svc.check(req("sec-src", "/p", "ok=2"));
        assertEquals(DecisionReason.ALLOWED, a1.reason());
        assertEquals(DecisionReason.ALLOWED, a2.reason());
        log.info("[编排] 安全拒绝不占用限流配额，正常流量仍获完整配额");
    }

    @Test
    void statsAreInternallyConsistent() {
        TrafficShieldService svc = newService(2, 60);
        svc.check(req("s", "/a", "1%20or%201=1"));   // SQL 安全拒绝
        svc.check(req("s", "/a", "x=<script>"));      // XSS 安全拒绝
        svc.check(req("s", "/a", "ok=1"));            // 放行 1
        svc.check(req("s", "/a", "ok=2"));            // 放行 2
        svc.check(req("s", "/a", "ok=3"));            // 限流 1
        svc.check(req("s", "/a", "ok=4"));            // 限流 2

        ShieldStats st = svc.stats();
        long securitySum = st.securityRejected().values().stream().mapToLong(Long::longValue).sum();
        log.info("[统计] total={} allowed={} security={} rateLimited={} 明细={}",
                st.total(), st.allowed(), securitySum, st.rateLimited(), st.securityRejected());

        assertEquals(6, st.total());
        assertEquals(2, st.allowed());
        assertEquals(2, st.rateLimited());
        assertEquals(2, securitySum);
        assertEquals(st.total(), st.allowed() + securitySum + st.rateLimited(),
                "统计快照必须满足 total = 放行 + 安全拒绝 + 限流");
        assertEquals(1L, st.securityRejected().get("SQL_INJECTION"));
        assertEquals(1L, st.securityRejected().get("XSS"));
        assertTrue(st.rulesVersion() >= 1);
    }
}

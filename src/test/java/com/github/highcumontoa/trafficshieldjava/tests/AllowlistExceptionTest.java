package com.github.highcumontoa.trafficshieldjava.tests;

import com.github.highcumontoa.trafficshieldjava.config.ShieldProperties;
import com.github.highcumontoa.trafficshieldjava.model.AllowlistException;
import com.github.highcumontoa.trafficshieldjava.model.DecisionReason;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 误拦例外测试：确认正常的业务流量按 （来源， 路径） 例外放行；
 * 明显攻击（内置编码特征）不受例外影响；例外配置整体校验、非法整体拒绝。
 */
class AllowlistExceptionTest {

    private static final Logger log = LoggerFactory.getLogger(AllowlistExceptionTest.class);

    /** CMS 后台更新图片模板：body 里的 &lt;img&gt; 标签会被 XSS-004 误拦。 */
    private static final String BUSINESS_BODY = "{\"template\": \"<img src=/static/logo.png>\"}";

    private TrafficShieldService newService() {
        ShieldProperties p = new ShieldProperties();
        p.setDefaultLimit(1_000_000);
        p.setDefaultWindowSeconds(60);
        return new TrafficShieldService(p);
    }

    private ShieldRequest req(String source, String path, String query, String body) {
        return new ShieldRequest("POST", path, query, Map.of(), body, source);
    }

    @Test
    void legitimateTrafficIsNoLongerBlockedAfterException() {
        TrafficShieldService svc = newService();

        // 例外配置前：正常业务请求被签名规则误拦
        ShieldDecision before = svc.check(req("cms-admin-1", "/api/templates", null, BUSINESS_BODY));
        assertFalse(before.allowed());
        assertEquals(DecisionReason.XSS, before.reason());
        log.info("[误拦例外] 配置前正常业务请求被误拦: reason={} rule={}", before.reason(), before.ruleId());

        // 运营配置例外：（来源 cms-*，路径 /api/templates）
        svc.updateRules(new RuleUpdateRequest(null, null, null, List.of(
                new AllowlistException("EX-CMS-TEMPLATE", "cms-*", "/api/templates"))));

        ShieldDecision after = svc.check(req("cms-admin-1", "/api/templates", null, BUSINESS_BODY));
        log.info("[误拦例外] 配置后同一业务请求: allowed={} reason={}", after.allowed(), after.reason());
        assertTrue(after.allowed(), "命中例外的正常业务流量必须放行");
    }

    @Test
    void obviousAttackIsNotLetThroughByException() {
        TrafficShieldService svc = newService();
        svc.updateRules(new RuleUpdateRequest(null, null, null, List.of(
                new AllowlistException("EX-CMS-TEMPLATE", "cms-*", "/api/templates"))));

        // 同一来源同一路径，但带明显攻击特征（双重编码）：例外不得豁免内置编码检查
        ShieldDecision doubleEncoded = svc.check(
                req("cms-admin-1", "/api/templates", "name=%252e%252e%252fetc", null));
        assertFalse(doubleEncoded.allowed());
        assertEquals(DecisionReason.SUSPICIOUS_ENCODING, doubleEncoded.reason());

        // 空字节同样不放过
        ShieldDecision nullByte = svc.check(
                req("cms-admin-1", "/api/templates", "name=a%00b", null));
        assertFalse(nullByte.allowed());
        assertEquals(DecisionReason.SUSPICIOUS_ENCODING, nullByte.reason());
        log.info("[误拦例外] 明显攻击不被例外放过: 双重编码=>{} 空字节=>{}",
                doubleEncoded.ruleId(), nullByte.ruleId());
    }

    @Test
    void exceptionOnlyAppliesToMatchingSourceAndPath() {
        TrafficShieldService svc = newService();
        svc.updateRules(new RuleUpdateRequest(null, null, null, List.of(
                new AllowlistException("EX-CMS-TEMPLATE", "cms-*", "/api/templates"))));

        // 路径不匹配：同一来源在别的路径上仍被拦
        ShieldDecision otherPath = svc.check(req("cms-admin-1", "/api/articles", null, BUSINESS_BODY));
        assertFalse(otherPath.allowed());
        assertEquals(DecisionReason.XSS, otherPath.reason());

        // 来源不匹配：其他来源在同一路径上仍被拦
        ShieldDecision otherSource = svc.check(req("anon-1", "/api/templates", null, BUSINESS_BODY));
        assertFalse(otherSource.allowed());
        assertEquals(DecisionReason.XSS, otherSource.reason());
        log.info("[误拦例外] 例外严格按（来源,路径）生效: 其他路径=>{} 其他来源=>{}",
                otherPath.reason(), otherSource.reason());
    }

    @Test
    void illegalExceptionConfigIsRejectedAndOldExceptionsRemain() {
        TrafficShieldService svc = newService();
        svc.updateRules(new RuleUpdateRequest(null, null, null, List.of(
                new AllowlistException("EX-CMS-TEMPLATE", "cms-*", "/api/templates"))));
        long versionBefore = svc.currentRules().version();

        // 非法：id 为空
        assertThrows(IllegalRuleException.class, () -> svc.updateRules(
                new RuleUpdateRequest(null, null, null, List.of(
                        new AllowlistException("", "a-*", "/x")))));
        // 非法：id 重复
        assertThrows(IllegalRuleException.class, () -> svc.updateRules(
                new RuleUpdateRequest(null, null, null, List.of(
                        new AllowlistException("DUP", "a-*", "/x"),
                        new AllowlistException("DUP", "b-*", "/y")))));
        // 非法：pathPattern 为空
        assertThrows(IllegalRuleException.class, () -> svc.updateRules(
                new RuleUpdateRequest(null, null, null, List.of(
                        new AllowlistException("EX-BAD", "a-*", " ")))));
        // 非法：sourcePattern 为空
        assertThrows(IllegalRuleException.class, () -> svc.updateRules(
                new RuleUpdateRequest(null, null, null, List.of(
                        new AllowlistException("EX-BAD2", null, "/x")))));

        assertEquals(versionBefore, svc.currentRules().version(),
                "非法例外配置必须整体拒绝，版本不变");
        assertEquals(1, svc.currentRules().allowlistExceptions().size(), "旧例外表必须保留");

        // 旧例外仍然生效，判定结果不忽好忽坏
        ShieldDecision d = svc.check(req("cms-admin-1", "/api/templates", null, BUSINESS_BODY));
        log.info("[误拦例外] 非法配置拒绝后旧例外仍生效: allowed={} version={}",
                d.allowed(), d.rulesVersion());
        assertTrue(d.allowed());
        assertEquals(versionBefore, d.rulesVersion());
    }
}

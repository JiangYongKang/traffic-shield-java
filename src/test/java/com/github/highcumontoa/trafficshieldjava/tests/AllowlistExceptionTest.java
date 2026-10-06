package com.github.highcumontoa.trafficshieldjava.tests;

import com.github.highcumontoa.trafficshieldjava.config.ShieldProperties;
import com.github.highcumontoa.trafficshieldjava.model.AllowlistException;
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
 * 误拦例外测试：确属正常的业务流量按 (来源, 路径) 维度豁免指定签名规则后放行；
 * 明显攻击（内置 ENC-* 编码检查、未豁免的签名规则、非匹配维度）仍然拦截；
 * 例外配置整体校验，非法时整体拒绝并保留旧配置。
 */
class AllowlistExceptionTest {

    private static final Logger log = LoggerFactory.getLogger(AllowlistExceptionTest.class);

    /** 业务方正常查询，但 "or 1=1" 片段会命中默认签名 SQL-003（典型误拦场景）。 */
    private static final String BUSINESS_QUERY = "filter=status%20or%201=1";

    private TrafficShieldService newService() {
        ShieldProperties p = new ShieldProperties();
        p.setDefaultLimit(1000);
        p.setDefaultWindowSeconds(60);
        return new TrafficShieldService(p);
    }

    private ShieldRequest req(String source, String path, String query) {
        return new ShieldRequest("GET", path, query, Map.of(), null, source);
    }

    private long installException(TrafficShieldService svc) {
        AllowlistException ex = new AllowlistException(
                "EX-PARTNER", "partner-*", "/api/orders", List.of("SQL-003"));
        return svc.updateRules(new RuleUpdateRequest(null, null, null, List.of(ex)));
    }

    @Test
    void normalTrafficNoLongerBlockedAfterException() {
        TrafficShieldService svc = newService();

        // 例外配置前：正常业务查询被 SQL-003 误拦
        ShieldDecision before = svc.check(req("partner-1", "/api/orders", BUSINESS_QUERY));
        assertEquals(DecisionReason.SQL_INJECTION, before.reason());
        assertEquals("SQL-003", before.ruleId());
        log.info("[误拦例外] 配置前：业务查询被误拦 ruleId={}", before.ruleId());

        long version = installException(svc);

        // 例外配置后：同一请求放行，且判定来自新版本规则
        ShieldDecision after = svc.check(req("partner-1", "/api/orders", BUSINESS_QUERY));
        assertEquals(DecisionReason.ALLOWED, after.reason());
        assertEquals(version, after.rulesVersion());
        log.info("[误拦例外] 配置后：同一业务查询放行, version {} -> {}", before.rulesVersion(), version);
    }

    @Test
    void exceptionDoesNotWhitelistOtherRulesSourcesOrPaths() {
        TrafficShieldService svc = newService();
        installException(svc);

        // 同一来源同一路径：命中未被豁免的 SQL-002（union select）仍然拦截
        ShieldDecision otherRule = svc.check(req("partner-1", "/api/orders", "q=1%20union%20select%20x"));
        assertEquals(DecisionReason.SQL_INJECTION, otherRule.reason());
        assertEquals("SQL-002", otherRule.ruleId());

        // 其他来源：同一被豁免片段仍然拦截（来源维度不匹配）
        ShieldDecision otherSource = svc.check(req("stranger-1", "/api/orders", BUSINESS_QUERY));
        assertEquals(DecisionReason.SQL_INJECTION, otherSource.reason());

        // 其他路径：同一被豁免片段仍然拦截（路径维度不匹配）
        ShieldDecision otherPath = svc.check(req("partner-1", "/api/users", BUSINESS_QUERY));
        assertEquals(DecisionReason.SQL_INJECTION, otherPath.reason());

        log.info("[误拦例外] 例外严格限定维度：未豁免规则/非匹配来源/非匹配路径均仍拦截");
    }

    @Test
    void obviousAttacksAreNeverExempted() {
        TrafficShieldService svc = newService();
        installException(svc);

        // 双重编码：明显攻击特征，内置 ENC-* 检查不接受任何例外
        ShieldDecision doubleEncoded = svc.check(
                req("partner-1", "/api/orders", "name=%252e%252e%252fetc"));
        assertEquals(DecisionReason.SUSPICIOUS_ENCODING, doubleEncoded.reason());
        assertEquals("ENC-DOUBLE-ENCODED", doubleEncoded.ruleId());

        // 空字节：同样不可豁免
        ShieldDecision nullByte = svc.check(
                req("partner-1", "/api/orders", "name=a%00.txt"));
        assertEquals(DecisionReason.SUSPICIOUS_ENCODING, nullByte.reason());

        // 内置 ENC-* 不是签名规则，无法被配置为豁免目标（配置即非法）
        assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(null, null, null,
                        List.of(new AllowlistException("EX-BAD", null, "/**",
                                List.of("ENC-DOUBLE-ENCODED"))))));

        log.info("[误拦例外] 明显攻击（双重编码/空字节）不受例外影响，ENC-* 也无法被配置豁免");
    }

    @Test
    void illegalExceptionConfigIsRejectedWhollyAndOldConfigRemains() {
        TrafficShieldService svc = newService();
        long version = installException(svc);

        // 非法：豁免列表为空
        IllegalRuleException e1 = assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(null, null, null,
                        List.of(new AllowlistException("EX-X", "a-*", null, List.of())))));
        // 非法：豁免的规则不存在
        IllegalRuleException e2 = assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(null, null, null,
                        List.of(new AllowlistException("EX-X", "a-*", null, List.of("NO-SUCH-RULE"))))));
        // 非法：来源与路径维度同时为空
        IllegalRuleException e3 = assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(null, null, null,
                        List.of(new AllowlistException("EX-X", null, null, List.of("SQL-003"))))));
        // 非法：例外 id 重复
        IllegalRuleException e4 = assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(null, null, null,
                        List.of(new AllowlistException("EX-D", "a-*", null, List.of("SQL-003")),
                                new AllowlistException("EX-D", "b-*", null, List.of("SQL-003"))))));
        log.warn("[误拦例外] 非法例外被整体拒绝: [{}] [{}] [{}] [{}]",
                e1.getMessage(), e2.getMessage(), e3.getMessage(), e4.getMessage());

        // 旧例外配置与版本保持不变，生效中的豁免语义不抖动
        assertEquals(version, svc.currentRules().version());
        assertEquals(1, svc.currentRules().allowlistExceptions().size());
        assertEquals(DecisionReason.ALLOWED,
                svc.check(req("partner-1", "/api/orders", BUSINESS_QUERY)).reason());
        assertEquals(DecisionReason.SQL_INJECTION,
                svc.check(req("stranger-1", "/api/orders", BUSINESS_QUERY)).reason());
        log.info("[误拦例外] 非法更新后旧例外完整保留并继续生效，version={}", version);
    }

    @Test
    void combinedUpdateIsAllOrNothing() {
        TrafficShieldService svc = newService();
        long versionBefore = svc.currentRules().version();

        // 一次更新同时携带合法档位与非法例外：整次拒绝，档位也不生效
        assertThrows(IllegalRuleException.class,
                () -> svc.updateRules(new RuleUpdateRequest(null, null,
                        List.of(new SourceTierRule("TIER-X", "internal-*", "/**", 5, 60)),
                        List.of(new AllowlistException("EX-X", null, null, List.of("SQL-003"))))));
        assertEquals(versionBefore, svc.currentRules().version());
        assertTrue(svc.currentRules().tierRules().isEmpty());
        assertTrue(svc.currentRules().allowlistExceptions().isEmpty());

        // 四部分全部合法：一次原子生效
        long v = svc.updateRules(new RuleUpdateRequest(null, null,
                List.of(new SourceTierRule("TIER-X", "internal-*", "/**", 5, 60)),
                List.of(new AllowlistException("EX-P", "partner-*", null, List.of("SQL-003")))));
        assertEquals(1, svc.currentRules().tierRules().size());
        assertEquals(1, svc.currentRules().allowlistExceptions().size());
        assertEquals(DecisionReason.ALLOWED,
                svc.check(req("partner-1", "/api/orders", BUSINESS_QUERY)).reason());
        log.info("[误拦例外] 组合更新满足全有或全无：非法时整体拒绝，合法时四部分同时生效, version={}", v);
    }
}

package com.github.highcumontoa.trafficshieldjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.highcumontoa.trafficshieldjava.shield.config.DefaultRules;
import com.github.highcumontoa.trafficshieldjava.shield.config.InvalidRuleException;
import com.github.highcumontoa.trafficshieldjava.shield.config.ShieldConfig;
import com.github.highcumontoa.trafficshieldjava.shield.model.Decision;
import com.github.highcumontoa.trafficshieldjava.shield.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.shield.model.RejectReason;
import com.github.highcumontoa.trafficshieldjava.shield.model.RequestContext;
import com.github.highcumontoa.trafficshieldjava.shield.model.ShieldResult;
import com.github.highcumontoa.trafficshieldjava.shield.ratelimit.RateLimiter;
import com.github.highcumontoa.trafficshieldjava.shield.security.SecurityInspector;
import com.github.highcumontoa.trafficshieldjava.shield.service.ShieldService;
import com.github.highcumontoa.trafficshieldjava.shield.stats.ShieldStats;
import com.github.highcumontoa.trafficshieldjava.shield.stats.StatsSnapshot;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 防护门面单测：原子更新、非法规则保留原规则、统计一致、判定可解释。
 */
class ShieldServiceTest {

    private static final Logger log = LoggerFactory.getLogger(ShieldServiceTest.class);

    private ShieldService newService() {
        return new ShieldService(DefaultRules.defaultConfig(),
                new SecurityInspector(), new RateLimiter(), new ShieldStats());
    }

    private RequestContext req(String source, String path, String query, String body) {
        return new RequestContext(source, "GET", path, query, Map.of(), body);
    }

    @Test
    void invalidRulesMustBeRejectedAndKeptIntact() {
        ShieldService service = newService();
        ShieldConfig before = service.currentConfig();
        int beforeCount = before.securityRules().size();

        // 非法配置：限流配额为 0
        ShieldConfig invalid = new ShieldConfig(
                before.securityRules(), List.of(new RateLimitRule("X", "/api/hello", 0, 1000L)));
        assertThrows(InvalidRuleException.class, () -> service.updateConfig(invalid));

        assertSame(before, service.currentConfig(), "非法更新后必须仍是原配置对象");
        assertEquals(beforeCount, service.currentConfig().securityRules().size());
        log.info("[test] 非法规则被拒绝，原规则保留: securityRules={}", beforeCount);

        // 原规则继续生效
        ShieldResult stillBlocked = service.check(req("s", "/p/../x", null, null));
        assertEquals(Decision.REJECT_SECURITY, stillBlocked.decision());
        assertEquals(RejectReason.PATH_TRAVERSAL, stillBlocked.reason());
    }

    @Test
    void validUpdateTakesEffectAtomically() {
        ShieldService service = newService();
        // 默认规则下 /api/hello 配额 10
        for (int i = 0; i < 10; i++) {
            assertEquals(Decision.ALLOW, service.check(req("s", "/api/hello", null, null)).decision());
        }
        assertEquals(Decision.REJECT_RATE_LIMIT,
                service.check(req("s", "/api/hello", null, null)).decision());

        // 更新为更严格的新规则（重置计数）
        ShieldConfig tighter = new ShieldConfig(
                DefaultRules.defaultConfig().securityRules(),
                List.of(new RateLimitRule("RL-HELLO", "/api/hello", 2, 1_000L)));
        service.updateConfig(tighter);
        assertEquals(2, service.currentConfig().rateLimitRules().get(0).limit());

        assertEquals(Decision.ALLOW, service.check(req("s", "/api/hello", null, null)).decision());
        assertEquals(Decision.ALLOW, service.check(req("s", "/api/hello", null, null)).decision());
        ShieldResult blocked = service.check(req("s", "/api/hello", null, null));
        assertEquals(Decision.REJECT_RATE_LIMIT, blocked.decision());
        assertTrue(blocked.retryAfterMillis() > 0, "限流必须带可重试提示");
        log.info("[test] 新规则生效: 配额=2, 第三次被限流 retryAfterMs={}", blocked.retryAfterMillis());
    }

    @Test
    void statsMustStayConsistentAndExplainable() {
        ShieldService service = newService();
        // 3 次正常、1 次注入、对 /api/submit(默认配额 5) 发起 7 次（5 放行 2 限流）
        service.check(req("s", "/api/hello", "name=ok", null));
        service.check(req("s", "/api/hello", "name=ok", null));
        service.check(req("s", "/other", null, null));
        ShieldResult injected = service.check(req("s", "/api/hello", "q=' or '1'='1", null));
        assertNotNull(injected.ruleId());

        int allowedOnSubmit = 0;
        int limitedOnSubmit = 0;
        for (int i = 0; i < 7; i++) {
            ShieldResult r = service.check(new RequestContext("s", "POST", "/api/submit", null, Map.of(), null));
            if (r.decision() == Decision.ALLOW) {
                allowedOnSubmit++;
            } else if (r.decision() == Decision.REJECT_RATE_LIMIT) {
                limitedOnSubmit++;
            }
        }
        assertEquals(5, allowedOnSubmit);
        assertEquals(2, limitedOnSubmit);

        StatsSnapshot snap = service.statsSnapshot();
        // total 11 = 放行 8(2 hello + 1 other + 5 submit) + 安全拒绝 1 + 限流 2
        assertEquals(11L, snap.total());
        assertEquals(8L, snap.allowed());
        assertEquals(1L, snap.rejected());
        assertEquals(2L, snap.rateLimited());
        assertEquals(1L, snap.rejectedByReason().get(RejectReason.SQL_INJECTION));
        assertEquals(2L, snap.rejectedByReason().get(RejectReason.RATE_LIMITED));
        assertEquals(snap.total(), snap.allowed() + snap.rejected() + snap.rateLimited(),
                "统计总数必须与分项之和一致");
        log.info("[test] 统计自洽 total={}, allowed={}, rejected={}, rateLimited={}, byReason={}",
                snap.total(), snap.allowed(), snap.rejected(), snap.rateLimited(),
                snap.rejectedByReason());
    }
}

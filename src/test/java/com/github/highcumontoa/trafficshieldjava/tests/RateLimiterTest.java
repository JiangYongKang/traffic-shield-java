package com.github.highcumontoa.trafficshieldjava.tests;

import com.github.highcumontoa.trafficshieldjava.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.ratelimit.RateLimiter;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 限流器单测：固定窗口内精确放行 limit 次，之后限流；窗口结束后新窗口重新放行。
 */
class RateLimiterTest {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterTest.class);

    private final RateLimiter limiter = new RateLimiter();
    private final List<RateLimitRule> rules = List.of(
            new RateLimitRule("RL-T", "/api/**", 3, 1));

    @Test
    void fixedWindowAllowsExactlyLimitThenRejects() {
        long t0 = 10_000L;
        int allowedCnt = 0;
        int limitedCnt = 0;
        RateLimiter.Denied denied = null;
        for (int i = 1; i <= 8; i++) {
            RateLimiter.Denied d = limiter.tryAcquire(rules, "src-A", "/api/x", t0 + 100 * i);
            if (d == null) {
                allowedCnt++;
            } else {
                limitedCnt++;
                denied = d;
            }
        }
        log.info("[限流-单线程] 8 个请求（配额3/1秒）=> 放行 {}，限流 {}", allowedCnt, limitedCnt);
        assertEquals(3, allowedCnt, "窗口内必须精确放行 3 次");
        assertEquals(5, limitedCnt, "之后必须全部限流，不能重复放行");
        assertNotNull(denied);
        assertEquals("RL-T", denied.ruleId());
        assertTrue(denied.retryAfterSeconds() >= 1, "必须给出可重试秒数");
        log.info("[限流-单线程] 限流结论 rule={} retryAfter={}s windowResetMs={}",
                denied.ruleId(), denied.retryAfterSeconds(), denied.windowResetMs());
    }

    @Test
    void limitIsPerSourceAndPerRule() {
        long t = 20_000L;
        for (int i = 0; i < 3; i++) {
            assertNull(limiter.tryAcquire(rules, "src-B", "/api/x", t + i));
        }
        // B 已超限；不同来源 C 不受影响
        assertNotNull(limiter.tryAcquire(rules, "src-B", "/api/x", t + 5));
        assertNull(limiter.tryAcquire(rules, "src-C", "/api/x", t + 5));
        log.info("[限流-按来源] 来源B超限后第4次被限流，来源C独立计数放行");
    }

    @Test
    void windowRotatesOnlyAfterRealTimeElapses() {
        long t0 = 30_000L;
        for (int i = 0; i < 3; i++) {
            assertNull(limiter.tryAcquire(rules, "src-D", "/api/x", t0 + i));
        }
        // 窗口未结束：仍然限流，不能提前解除
        assertNotNull(limiter.tryAcquire(rules, "src-D", "/api/x", t0 + 999));
        log.info("[限流-窗口] 窗口结束前请求仍被限流（不提前解除）");

        // 越过窗口边界：新窗口重新放行
        assertNull(limiter.tryAcquire(rules, "src-D", "/api/x", t0 + 1_001));
        log.info("[限流-窗口] 窗口结束后新窗口重新放行");
    }

    @Test
    void unmatchedPathIsNotCounted() {
        long t = 40_000L;
        for (int i = 0; i < 10; i++) {
            assertNull(limiter.tryAcquire(rules, "src-E", "/other/path", t + i));
        }
        assertEquals(0, limiter.currentCount("src-E", "RL-T", t + 11));
        log.info("[限流-路径] 不匹配规则的路径不计数");
    }
}

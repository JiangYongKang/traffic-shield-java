package com.github.highcumontoa.trafficshieldjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.highcumontoa.trafficshieldjava.shield.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.shield.model.RateLimitVerdict;
import com.github.highcumontoa.trafficshieldjava.shield.ratelimit.RateLimiter;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 限流器单测：突发并发下计数准确，来源相互隔离，窗口到期才解除限制。
 */
class RateLimiterTest {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterTest.class);

    private final RateLimitRule rule = new RateLimitRule("RL-T", "/api/t", 100, 1_000L);

    @Test
    void concurrentBurstAllowsExactlyTheLimit() throws InterruptedException {
        RateLimiter limiter = new RateLimiter();
        int threads = 50;
        int perThread = 4; // 共 200 次请求，配额 100
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        ExecutorService pool = Executors.newFixedThreadPool(threads);

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int j = 0; j < perThread; j++) {
                        RateLimitVerdict v = limiter.tryAcquire(rule, "src-A", System.nanoTime() / 1_000_000L);
                        (v.allowed() ? allowed : rejected).incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdown();

        log.info("[test] 并发突发 total=200, 放行={}, 拒绝={}", allowed.get(), rejected.get());
        assertEquals(100, allowed.get(), "放行次数必须恰好等于配额，不得重复放行或计数丢失");
        assertEquals(100, rejected.get());
    }

    @Test
    void sourcesAreIsolated() {
        RateLimiter limiter = new RateLimiter();
        RateLimitRule small = new RateLimitRule("RL-S", "/api/s", 2, 1_000L);
        long now = 5_000L;
        assertTrue(limiter.tryAcquire(small, "src-1", now).allowed());
        assertTrue(limiter.tryAcquire(small, "src-1", now + 10).allowed());
        assertFalse(limiter.tryAcquire(small, "src-1", now + 20).allowed());

        // 另一个来源仍拥有完整配额
        RateLimitVerdict other = limiter.tryAcquire(small, "src-2", now + 30);
        assertTrue(other.allowed());
        log.info("[test] 来源隔离 src-1 超限后 src-2 首次判定 allowed={}", other.allowed());
    }

    @Test
    void limitMustNotReleaseBeforeWindowEnds() {
        RateLimiter limiter = new RateLimiter();
        RateLimitRule small = new RateLimitRule("RL-W", "/api/w", 1, 1_000L);
        long t0 = 10_000L;
        assertTrue(limiter.tryAcquire(small, "src", t0).allowed());

        // 窗口边界之前的任意时刻都必须拒绝
        assertFalse(limiter.tryAcquire(small, "src", t0 + 500).allowed());
        assertFalse(limiter.tryAcquire(small, "src", t0 + 999).allowed());

        // 恰好在窗口结束时刻解除
        RateLimitVerdict released = limiter.tryAcquire(small, "src", t0 + 1000);
        assertTrue(released.allowed());
        log.info("[test] 窗口语义 t0+999 拒绝, t0+1000 放行");
    }

    @Test
    void rejectionProvidesRetryHint() {
        RateLimiter limiter = new RateLimiter();
        RateLimitRule small = new RateLimitRule("RL-R", "/api/r", 1, 1_000L);
        long t0 = 7_000L;
        limiter.tryAcquire(small, "src", t0);
        RateLimitVerdict rejected = limiter.tryAcquire(small, "src", t0 + 250);
        assertFalse(rejected.allowed());
        assertTrue(rejected.retryAfterMillis() > 0 && rejected.retryAfterMillis() <= 750,
                "retryAfter 必须为窗口剩余时间");
        log.info("[test] 可重试提示 retryAfterMs={}", rejected.retryAfterMillis());
    }
}

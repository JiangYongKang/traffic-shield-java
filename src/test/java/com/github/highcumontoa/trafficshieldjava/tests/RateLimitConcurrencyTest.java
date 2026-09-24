package com.github.highcumontoa.trafficshieldjava.tests;

import com.github.highcumontoa.trafficshieldjava.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.ratelimit.RateLimiter;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 限流器并发测试：突发并发下计数准确，放行数严格等于窗口配额。
 */
class RateLimitConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(RateLimitConcurrencyTest.class);

    @Test
    void concurrentBurstAllowsExactlyTheLimit() throws InterruptedException {
        int limit = 50;
        int threads = 500;
        RateLimiter limiter = new RateLimiter();
        List<RateLimitRule> rules = List.of(
                new RateLimitRule("RL-C", "/burst/**", limit, 60));
        long now = System.currentTimeMillis();

        ExecutorService pool = Executors.newFixedThreadPool(32);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    RateLimiter.Denied d = limiter.tryAcquire(rules, "concurrent-src", "/burst/go", now);
                    if (d == null) {
                        allowed.incrementAndGet();
                    } else {
                        rejected.incrementAndGet();
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
        pool.shutdownNow();

        log.info("[限流-并发] {} 个并发请求，配额 {} => 放行 {}，限流 {}",
                threads, limit, allowed.get(), rejected.get());
        assertEquals(limit, allowed.get(),
                "并发下放行数必须严格等于配额，不得丢失计数或重复放行");
        assertEquals(threads - limit, rejected.get(),
                "其余请求必须全部被限流");
        assertEquals(threads, allowed.get() + rejected.get(), "结论总数必须自洽");
    }
}

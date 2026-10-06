package com.github.highcumontoa.trafficshieldjava.tests;

import com.github.highcumontoa.trafficshieldjava.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.ratelimit.RateLimiter;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 高基数来源下的状态容量治理测试：状态数量有明确上限，超限按 LRU 回收；
 * 被回收来源在窗口仍有效时再次出现，恢复原计数、同一窗口不多放行；
 * 回收与正常判定并发执行不报错且计数自洽。
 */
class StateCapacityGovernanceTest {

    private static final Logger log = LoggerFactory.getLogger(StateCapacityGovernanceTest.class);

    private static final List<RateLimitRule> RULES =
            List.of(new RateLimitRule("RL", "/**", 5, 60));

    @Test
    void overCapacityEvictsLruAndRestoresCountWithinSameWindow() {
        RateLimiter limiter = new RateLimiter(10);
        long base = System.currentTimeMillis();

        // 15 个来源依次到来（访问时间递增），上限 10 => 最久未使用的 s0..s4 被回收进墓碑区
        for (int i = 0; i < 15; i++) {
            assertNull(limiter.tryAcquire(RULES, "s" + i, "/a", base + i));
        }
        limiter.sweepExpired(base + 100);
        log.info("[容量治理] 15 个来源/上限 10 => 活跃窗口 {}, 墓碑窗口 {}",
                limiter.activeWindowCount(), limiter.evictedWindowCount());
        assertTrue(limiter.activeWindowCount() <= 10, "活跃状态不得超过容量上限");
        assertEquals(5, limiter.evictedWindowCount(), "被回收的活跃窗口应整体进入墓碑区");
        assertEquals(1, limiter.currentCount("s0", "RL", base + 100), "墓碑窗口计数原样保留");

        // 被回收的 s0 在同一有效窗口内再次出现：恢复原计数继续，不凭空多放行
        int allowed = 1; // 首次到来已放行 1 次
        for (int i = 0; i < 4; i++) {
            assertNull(limiter.tryAcquire(RULES, "s0", "/a", base + 1000 + i));
            allowed++;
        }
        assertEquals(5, allowed, "含回收前计数，同一窗口内总共只能放行 limit 次");
        assertEquals(5, limiter.currentCount("s0", "RL", base + 2000),
                "恢复后的窗口计数必须接续回收前的计数");
        RateLimiter.Denied denied = limiter.tryAcquire(RULES, "s0", "/a", base + 2000);
        assertTrue(denied != null && denied.ruleId().equals("RL"),
                "恢复后的窗口计满 limit 后必须继续限流");
        log.info("[容量治理] 被回收来源 s0 在同一窗口内再现：恢复计数，共放行 {} 次(=limit)后限流，未多放行",
                allowed);
    }

    @Test
    void sweepRemovesExpiredWindowsAndTombstones() {
        RateLimiter limiter = new RateLimiter(4);
        long base = System.currentTimeMillis();
        for (int i = 0; i < 8; i++) {
            limiter.tryAcquire(RULES, "e" + i, "/a", base + i);
        }
        limiter.sweepExpired(base + 100);
        assertTrue(limiter.activeWindowCount() <= 4);
        assertTrue(limiter.evictedWindowCount() > 0);

        // 窗口自然过期后：活跃区与墓碑区都被清空，不再保留任何状态
        limiter.sweepExpired(base + 120_000);
        assertEquals(0, limiter.activeWindowCount());
        assertEquals(0, limiter.evictedWindowCount());
        log.info("[容量治理] 窗口过期后活跃区与墓碑区全部清空，内存不随来源数无限增长");
    }

    @Test
    void concurrentAcquireAndSweepNeverFailAndCountsStayConsistent() throws InterruptedException {
        int sources = 200;
        int limit = 20;
        int requestsPerSource = 40;
        List<RateLimitRule> rules = List.of(new RateLimitRule("RL-C", "/**", limit, 600));
        RateLimiter limiter = new RateLimiter(150); // 容量 < 来源数，回收全程参与

        ExecutorService pool = Executors.newFixedThreadPool(32);
        CountDownLatch start = new CountDownLatch(1);
        Map<String, AtomicInteger> allowedPerSource = new ConcurrentHashMap<>();
        AtomicInteger errors = new AtomicInteger();
        AtomicReference<Throwable> firstError = new AtomicReference<>();
        AtomicBoolean stopSweep = new AtomicBoolean(false);
        AtomicLong sweepRounds = new AtomicLong();

        // 回收线程：与判定全程并发清理过期状态并执行容量回收
        Thread sweeper = new Thread(() -> {
            while (!stopSweep.get()) {
                try {
                    limiter.sweepExpired(System.currentTimeMillis());
                    sweepRounds.incrementAndGet();
                } catch (Throwable t) {
                    errors.incrementAndGet();
                    firstError.compareAndSet(null, t);
                }
            }
        }, "sweeper");
        sweeper.start();

        // 判定线程：200 个来源各发 40 个请求（配额 20），高基数触发持续回收
        for (int s = 0; s < sources; s++) {
            final String source = "hc-" + s;
            allowedPerSource.put(source, new AtomicInteger());
            for (int r = 0; r < requestsPerSource; r++) {
                pool.submit(() -> {
                    try {
                        start.await();
                        RateLimiter.Denied d = limiter.tryAcquire(rules, source, "/x",
                                System.currentTimeMillis());
                        if (d == null) {
                            allowedPerSource.get(source).incrementAndGet();
                        }
                    } catch (Throwable t) {
                        errors.incrementAndGet();
                        firstError.compareAndSet(null, t);
                    }
                });
            }
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS), "并发判定应在超时前结束");
        stopSweep.set(true);
        sweeper.join(10_000);

        assertEquals(0, errors.get(), () -> "回收与判定并发执行不得报错: " + firstError.get());

        int totalAllowed = 0;
        int exactSources = 0;
        for (Map.Entry<String, AtomicInteger> e : allowedPerSource.entrySet()) {
            int a = e.getValue().get();
            totalAllowed += a;
            if (a == limit) {
                exactSources++;
            } else {
                log.warn("[容量并发] 来源 {} 放行 {} 次，与配额 {} 不符", e.getKey(), a, limit);
            }
        }
        log.info("[容量并发] {} 来源 x {} 请求(配额 {})，回收 {} 轮 => 总放行 {}，"
                        + "恰好等于配额的来源 {}/{}，结束时活跃窗口 {}",
                sources, requestsPerSource, limit, sweepRounds.get(),
                totalAllowed, exactSources, sources, limiter.activeWindowCount());

        assertEquals(sources * limit, totalAllowed,
                "回收并发参与下，每个来源在同一窗口内放行数必须恰好等于配额（不多放行、不丢计数）");
        assertEquals(sources, exactSources);
        assertTrue(limiter.activeWindowCount() <= 150, "活跃状态数量必须始终受容量上限约束");
    }
}

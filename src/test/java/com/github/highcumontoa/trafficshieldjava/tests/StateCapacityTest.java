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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 状态容量治理测试：高基数来源下状态条目有明确上限；超限按"先过期、再降级影子、
 * 最后删影子"的策略回收；被回收来源在同一有效窗口内重现不会凭空多放行；
 * 回收/清理与并发判定同时发生时不报错且计数自洽。
 */
class StateCapacityTest {

    private static final Logger log = LoggerFactory.getLogger(StateCapacityTest.class);

    private static final List<RateLimitRule> RULE =
            List.of(new RateLimitRule("RL-CAP", "/**", 1000, 60));

    @Test
    void stateSizeIsBoundedUnderHighCardinalitySources() {
        RateLimiter limiter = new RateLimiter(50);
        long t0 = 100_000L;
        for (int i = 0; i < 300; i++) {
            limiter.tryAcquire(RULE, "src-" + i, "/api/x", t0 + i);
        }
        int live = limiter.liveWindowCount();
        int size = limiter.stateSize();
        log.info("[容量治理] 300 个高基数来源后存活窗口={} 状态条目总数={}（上限 50，总预算 100）",
                live, size);
        assertTrue(live <= 50, "存活窗口数不得超过容量上限，实际=" + live);
        assertTrue(size <= 100, "状态条目总数不得超过 2 倍容量预算（存活+影子），实际=" + size);
    }

    @Test
    void evictedSourceDoesNotGainExtraQuotaInSameWindow() {
        RateLimiter limiter = new RateLimiter(10);
        List<RateLimitRule> rule = List.of(new RateLimitRule("RL-HOT", "/**", 2, 60));
        long t0 = 1_000_000L;

        // 热点来源先用掉配额（限额 2）
        assertNull(limiter.tryAcquire(rule, "hot", "/a", t0));
        assertNull(limiter.tryAcquire(rule, "hot", "/a", t0));
        assertNotNull(limiter.tryAcquire(rule, "hot", "/a", t0), "第 3 次必须被限流");

        // 更晚出现的来源把 hot 的窗口挤出（hot 的窗口开始时间最早，优先被降级为影子；
        // 数量控制在影子预算内，验证影子恢复语义而非极端硬删）
        for (int i = 0; i < 15; i++) {
            limiter.tryAcquire(RULE, "cold-" + i, "/a", t0 + 1 + i);
        }

        // hot 在同一个仍有效的窗口内重现：计数从影子恢复，不得凭空多放行
        RateLimiter.Denied denied = limiter.tryAcquire(rule, "hot", "/a", t0 + 1_000);
        assertNotNull(denied, "被回收来源在同一有效窗口内重现不得获得新配额");
        long count = limiter.currentCount("hot", "RL-HOT", t0 + 1_000);
        log.info("[容量治理] hot 窗口被回收后重现: 拒绝={} 窗口内累计计数={}（限额 2）",
                denied.ruleId(), count);
        assertTrue(count >= 3, "计数必须在回收前后连续，实际=" + count);

        // 窗口结束后：按新窗口重新计数，正常放行
        assertNull(limiter.tryAcquire(rule, "hot", "/a", t0 + 61_000),
                "窗口结束后必须按新窗口放行");
        log.info("[容量治理] 窗口结束后 hot 按新窗口重新计数并放行");
    }

    @Test
    void concurrentBurstWithEvictionAndSweepingStaysConsistent() throws InterruptedException {
        int capacity = 150;
        int limit = 50;
        int threads = 500;
        RateLimiter limiter = new RateLimiter(capacity);
        List<RateLimitRule> hotRule = List.of(new RateLimitRule("RL-HOT", "/hot/**", limit, 60));
        List<RateLimitRule> coldRule = List.of(new RateLimitRule("RL-COLD", "/cold/**", 1000, 1));
        long t0 = 2_000_000L;

        // 预置 300 个高基数冷来源（窗口 1s），触发容量回收
        for (int i = 0; i < 300; i++) {
            limiter.tryAcquire(coldRule, "cold-pre-" + i, "/cold/x", t0 + i % 500);
        }
        assertTrue(limiter.liveWindowCount() <= capacity, "预置阶段存活窗口必须已受控");
        assertTrue(limiter.stateSize() <= 2 * capacity, "预置阶段状态总量必须已受控");

        long burstTime = t0 + 2_000; // 冷来源窗口已过期，热点窗口严格更新，回收永远先选中冷条目
        ExecutorService pool = Executors.newFixedThreadPool(40);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads + 2);
        AtomicInteger allowed = new AtomicInteger();
        AtomicInteger denied = new AtomicInteger();
        AtomicInteger errors = new AtomicInteger();

        // 热点来源 500 并发突发（配额 50）
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    if (limiter.tryAcquire(hotRule, "hot", "/hot/go", burstTime) == null) {
                        allowed.incrementAndGet();
                    } else {
                        denied.incrementAndGet();
                    }
                } catch (Exception e) {
                    errors.incrementAndGet();
                } finally {
                    done.countDown();
                }
            });
        }
        // 并发的高基数冷来源持续制造回收压力
        pool.submit(() -> {
            try {
                start.await();
                for (int i = 0; i < 500; i++) {
                    limiter.tryAcquire(coldRule, "cold-live-" + i, "/cold/y", t0 + 1_500);
                }
            } catch (Exception e) {
                errors.incrementAndGet();
            } finally {
                done.countDown();
            }
        });
        // 并发的过期清理线程
        pool.submit(() -> {
            try {
                start.await();
                for (int i = 0; i < 200; i++) {
                    limiter.sweepExpired(burstTime);
                }
            } catch (Exception e) {
                errors.incrementAndGet();
            } finally {
                done.countDown();
            }
        });

        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "并发任务应在超时前结束");

        log.info("[容量治理-并发] 热点突发 {} 并发/配额 {} => 放行 {} 限流 {}；异常 {}；状态条目 {}（上限 {}）",
                threads, limit, allowed.get(), denied.get(), errors.get(),
                limiter.stateSize(), capacity);
        assertEquals(0, errors.get(), "回收/清理与判定并发执行不得出现任何异常");
        assertEquals(limit, allowed.get(), "回收并发下热点来源放行数必须精确等于配额");
        assertEquals(threads - limit, denied.get(), "其余请求必须全部被限流，计数自洽");
        assertEquals(threads, allowed.get() + denied.get(), "结论总数必须自洽");
        assertTrue(limiter.liveWindowCount() <= capacity,
                "并发回收期间存活窗口数不得超过上限，实际=" + limiter.liveWindowCount());
        assertTrue(limiter.stateSize() <= 2 * capacity,
                "并发回收期间状态条目总数不得超过 2 倍预算，实际=" + limiter.stateSize());
    }
}

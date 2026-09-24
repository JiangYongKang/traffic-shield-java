package com.github.highcumontoa.trafficshieldjava.tests;

import com.github.highcumontoa.trafficshieldjava.config.ShieldProperties;
import com.github.highcumontoa.trafficshieldjava.model.DecisionReason;
import com.github.highcumontoa.trafficshieldjava.model.RuleUpdateRequest;
import com.github.highcumontoa.trafficshieldjava.model.SecurityRule;
import com.github.highcumontoa.trafficshieldjava.model.ShieldDecision;
import com.github.highcumontoa.trafficshieldjava.model.ShieldRequest;
import com.github.highcumontoa.trafficshieldjava.service.TrafficShieldService;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规则更新与流量判定并发测试：更新过程中每个请求的结论都必须来自某一张完整规则表，
 * 不允许出现新旧规则混合判定。
 *
 * <p>验证方法：反复在两张合法规则表（A: 拦 SQL、B: 拦自定义词）之间切换，
 * 并发发送分别只应被 A / 被 B 命中的请求。A、B 是整表替换：
 * 版本为 A 时自定义词必须放行；版本为 B 时 SQL 必须放行；任何交叉结论都意味着混用。</p>
 */
class RuleUpdateConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(RuleUpdateConcurrencyTest.class);

    private final List<SecurityRule> rulesA = List.of(
            new SecurityRule("A-ONLY", "A规则-拦SQL", DecisionReason.SQL_INJECTION.name(),
                    "union\\s+select"));
    private final List<SecurityRule> rulesB = List.of(
            new SecurityRule("B-ONLY", "B规则-拦自定义词", DecisionReason.XSS.name(),
                    "marker-b-token"));

    @Test
    void concurrentChecksDuringUpdatesNeverMixRules() throws InterruptedException {
        ShieldProperties p = new ShieldProperties();
        p.setDefaultLimit(1_000_000); // 放大限流配额，本测试只关注规则一致性
        p.setDefaultWindowSeconds(60);
        TrafficShieldService svc = new TrafficShieldService(p);

        int writerRounds = 200;
        int checkers = 8;
        int perChecker = 2_000;

        ExecutorService pool = Executors.newFixedThreadPool(checkers + 1);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger violations = new AtomicInteger();
        AtomicInteger totalChecks = new AtomicInteger();

        // 更新线程：在 A/B 间反复整表切换
        pool.submit(() -> {
            try {
                start.await();
                for (int i = 0; i < writerRounds; i++) {
                    List<SecurityRule> next = (i % 2 == 0) ? rulesA : rulesB;
                    svc.updateRules(new RuleUpdateRequest(next, null));
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        // 判定线程：交替发只对 A 或只对 B 敏感的请求
        for (int c = 0; c < checkers; c++) {
            final int idx = c;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perChecker; i++) {
                        boolean aProbe = (i + idx) % 2 == 0;
                        String query = aProbe ? "q=1%20union%20select%20x" : "q=marker-b-token";
                        ShieldRequest r = new ShieldRequest("GET", "/mix", query,
                                Map.of(), null, "mix-src-" + idx);
                        ShieldDecision d = svc.check(r);
                        long v = d.rulesVersion();
                        totalChecks.incrementAndGet();

                        // 版本 1 是初始默认规则（可能同时命中两者），跳过；
                        // 更新产生的版本：偶数版本装 A（SQL 拦截、B词放行），
                        // 奇数版本（>=3）装 B（B词拦截、SQL放行）。
                        if (v == 1L) {
                            continue;
                        }
                        if (aProbe) {
                            boolean onA = (v % 2 == 0);
                            if (onA) {
                                if (d.allowed() || d.reason() != DecisionReason.SQL_INJECTION) {
                                    violations.incrementAndGet();
                                }
                            } else {
                                if (!d.allowed()) {
                                    violations.incrementAndGet(); // B 表下 SQL 探针必须放行
                                }
                            }
                        } else {
                            boolean onA = (v % 2 == 0);
                            if (onA) {
                                if (!d.allowed()) {
                                    violations.incrementAndGet(); // A 表下 B 探针必须放行
                                }
                            } else {
                                if (d.allowed() || d.reason() != DecisionReason.XSS) {
                                    violations.incrementAndGet();
                                }
                            }
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "并发任务应在超时前结束");

        log.info("[规则并发] 更新 {} 轮，并发判定 {} 次，混用违例 {}",
                writerRounds, totalChecks.get(), violations.get());
        assertTrue(violations.get() == 0,
                "更新期间不得出现新旧规则混合判定，违例数=" + violations.get());
    }
}

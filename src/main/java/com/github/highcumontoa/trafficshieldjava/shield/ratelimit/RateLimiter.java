package com.github.highcumontoa.trafficshieldjava.shield.ratelimit;

import com.github.highcumontoa.trafficshieldjava.shield.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.shield.model.RateLimitVerdict;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 按来源与规则的固定窗口限流器（内存实现）。
 *
 * <p>每个 (规则, 来源) 组合拥有独立的 {@link CounterWindow} 与分段锁：
 * <ul>
 *   <li>窗口判定与计数自增在同一把 key 锁内完成，突发/并发下不会丢失计数或重复放行；</li>
 *   <li>仅当当前时间进入下一个窗口时才轮换，限制绝不会提前解除；</li>
 *   <li>被拒绝时返回距窗口重置的剩余毫秒数，用于 Retry-After 提示。</li>
 * </ul>
 * 本组件不持有规则列表，所有参数均来自调用方传入的配置快照，
 * 因而与配置原子更新天然一致。
 */
public class RateLimiter {

    private static final Logger log = LoggerFactory.getLogger(RateLimiter.class);

    private final Map<String, CounterWindow> windows = new ConcurrentHashMap<>();

    public RateLimiter() {
    }

    /**
     * 规则整体更新后清空计数（新规则集视为新的计量起点）。
     */
    public void reset() {
        windows.clear();
    }

    /**
     * 在指定规则与来源上尝试占用一次配额。
     */
    public RateLimitVerdict tryAcquire(RateLimitRule rule, String source, long nowMillis) {
        String key = rule.id() + "|" + source;
        CounterWindow window = windows.computeIfAbsent(
                key, k -> new CounterWindow(nowMillis, rule.windowMillis()));
        int current;
        boolean allowed;
        long retryAfter;

        // 分段锁：同一 key 的窗口轮换与计数严格串行，不同 key 之间互不阻塞
        synchronized (window) {
            if (nowMillis - window.getWindowStart() >= window.getWindowMillis()) {
                window.resetTo(nowMillis);
            }
            if (window.getCount() < rule.limit()) {
                current = window.increment();
                allowed = true;
                retryAfter = 0L;
            } else {
                current = window.getCount();
                allowed = false;
                retryAfter = window.getWindowMillis() - (nowMillis - window.getWindowStart());
            }
        }

        if (allowed) {
            log.info("[shield] 限流放行 rule={}, source={}, count={}/{}",
                    rule.id(), source, current, rule.limit());
        } else {
            log.info("[shield] 限流拒绝 rule={}, source={}, count={}/{}, retryAfterMs={}",
                    rule.id(), source, current, rule.limit(), retryAfter);
            evictExpired(nowMillis);
        }
        return new RateLimitVerdict(allowed, current, retryAfter);
    }

    private void evictExpired(long nowMillis) {
        windows.entrySet().removeIf(entry ->
                nowMillis - entry.getValue().getWindowStart() >= entry.getValue().getWindowMillis());
    }
}

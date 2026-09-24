package com.github.highcumontoa.trafficshieldjava.shield.ratelimit;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * 单个（规则+来源）维度的固定窗口计数器。
 *
 * <p>所有读写均在 {@link RateLimiter} 按 key 分段加锁后进行；
 * count 使用 AtomicInteger 仅为自增语义清晰，窗口轮换由外部同步保证。</p>
 */
public class CounterWindow {

    private final AtomicInteger count = new AtomicInteger(0);
    private volatile long windowStart;
    private final long windowMillis;

    public CounterWindow(long windowStart, long windowMillis) {
        this.windowStart = windowStart;
        this.windowMillis = windowMillis;
    }

    public long getWindowStart() {
        return windowStart;
    }

    public long getWindowMillis() {
        return windowMillis;
    }

    public void resetTo(long newWindowStart) {
        this.windowStart = newWindowStart;
        count.set(0);
    }

    public int increment() {
        return count.incrementAndGet();
    }

    public int getCount() {
        return count.get();
    }
}

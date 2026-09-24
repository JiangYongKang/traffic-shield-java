package com.github.highcumontoa.trafficshieldjava.shield.model;

/**
 * 限流组件的内部判定。
 */
public record RateLimitVerdict(boolean allowed, int currentCount, long retryAfterMillis) {
}

package com.github.highcumontoa.trafficshieldjava.shield.model;

/**
 * 一条固定窗口限流规则（按来源）。
 *
 * @param id          规则标识（同时作为匹配入口的 key）
 * @param pathPattern 需要限流的入口路径（精确匹配）
 * @param limit       窗口内最大放行次数
 * @param windowMillis 窗口长度（毫秒）
 */
public record RateLimitRule(String id, String pathPattern, int limit, long windowMillis) {
}

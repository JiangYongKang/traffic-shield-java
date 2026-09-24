package com.github.highcumontoa.trafficshieldjava.model;

/**
 * 一条固定时间窗口限流规则。
 *
 * @param id             规则唯一标识
 * @param pathPattern    匹配的请求路径（Ant 风格，如 /**）
 * @param limit          每个来源在一个窗口内允许的最大请求数
 * @param windowSeconds  固定窗口长度（秒）
 */
public record RateLimitRule(String id, String pathPattern, int limit, int windowSeconds) {
}

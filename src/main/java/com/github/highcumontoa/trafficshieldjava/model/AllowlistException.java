package com.github.highcumontoa.trafficshieldjava.model;

/**
 * 一条误拦例外：确认正常的流量可按 （来源， 路径） 维度豁免可配置签名规则的拦截。
 *
 * <p>安全边界：例外只豁免规则表中的签名规则（SQL/XSS/CMD/PATH 等可配置正则），
 * 内置的明显攻击特征检查（ENC-*：双重编码、空字节、畸形编码等）不受例外影响，
 * 因此配置例外不会把明显的攻击请求一起放过。</p>
 *
 * @param id            例外唯一标识
 * @param sourcePattern 匹配的请求来源（Ant 风格，如 {@code ops-*}；{@code **} 表示所有来源）
 * @param pathPattern   匹配的请求路径（Ant 风格，如 {@code /api/search}）
 */
public record AllowlistException(String id, String sourcePattern, String pathPattern) {
}

package com.github.highcumontoa.trafficshieldjava.model;

/**
 * 一条安全检测规则（正则签名）。
 *
 * @param id       规则唯一标识
 * @param name     规则名称
 * @param category 命中类别，取值为 {@link DecisionReason} 中的安全类原因名
 * @param pattern  正则表达式（大小写不敏感按 DOTALL 语义编译）
 */
public record SecurityRule(String id, String name, String category, String pattern) {
}

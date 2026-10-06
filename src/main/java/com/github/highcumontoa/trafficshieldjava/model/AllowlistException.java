package com.github.highcumontoa.trafficshieldjava.model;

import java.util.List;

/**
 * 一条误拦例外：对匹配的流量豁免指定的安全签名规则。
 *
 * <p>判定语义：{@code sourcePattern} / {@code pathPattern} 同时命中（Ant 风格通配，
 * 为 {@code null} 的维度视为不限制）时，{@code exemptRuleIds} 中列出的安全签名规则
 * 对该请求不再生效。内置的异常编码检查（ENC-*，如双重编码、空字节等明显攻击特征）
 * 不属于签名规则，任何例外都不能豁免，因此配置例外不会放过明显攻击。</p>
 *
 * @param id             例外唯一标识
 * @param sourcePattern  来源匹配模式（Ant 风格；null 表示不限来源）
 * @param pathPattern    路径匹配模式（Ant 风格；null 表示不限路径）
 * @param exemptRuleIds  被豁免的安全规则 id 列表（必须引用现存安全规则）
 */
public record AllowlistException(String id,
                                 String sourcePattern,
                                 String pathPattern,
                                 List<String> exemptRuleIds) {
}

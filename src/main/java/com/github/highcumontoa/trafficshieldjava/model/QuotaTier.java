package com.github.highcumontoa.trafficshieldjava.model;

/**
 * 一档来源分级配额：按来源重要程度划分的独立限流档位。
 *
 * <p>档位按声明顺序匹配，一个请求只落入首个 {@code sourcePattern} 命中其来源的档位，
 * 只按这一档计一次数；未命中任何档位的来源不受分级配额约束。
 * 各档位的计数窗口互相独立，互不影响。</p>
 *
 * @param id             档位唯一标识
 * @param sourcePattern  匹配的请求来源（Ant 风格，如 {@code internal-*}）
 * @param limit          每个来源在该档一个窗口内允许的最大请求数
 * @param windowSeconds  该档固定窗口长度（秒）
 */
public record QuotaTier(String id, String sourcePattern, int limit, int windowSeconds) {
}

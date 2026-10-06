package com.github.highcumontoa.trafficshieldjava.model;

/**
 * 一条来源分级限流档位：按来源重要程度划分额度。
 *
 * <p>判定语义：按列表声明顺序匹配，{@code sourcePattern} 与 {@code pathPattern}
 * 同时命中（Ant 风格通配）即归属该档位；一个请求只按首个命中的档位计一次数，
 * 不同档位的计数窗口互不影响。未命中任何档位的请求回退到普通限流规则。</p>
 *
 * @param id             档位唯一标识
 * @param sourcePattern  来源匹配模式（Ant 风格，如 {@code internal-*}、{@code 10.0.*}）
 * @param pathPattern    路径匹配模式（Ant 风格，如 {@code /**}）
 * @param limit          每个来源在该档位一个窗口内允许的最大请求数
 * @param windowSeconds  该档位的固定窗口长度（秒）
 */
public record SourceTierRule(String id,
                             String sourcePattern,
                             String pathPattern,
                             int limit,
                             int windowSeconds) {
}

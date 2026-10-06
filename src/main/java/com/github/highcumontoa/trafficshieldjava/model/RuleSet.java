package com.github.highcumontoa.trafficshieldjava.model;

import java.util.List;

/**
 * 某一时刻生效的完整规则集，整体不可变，原子替换。
 *
 * <p>{@code tierRules} 为来源分级限流档位（空列表表示未启用分级，全部走
 * {@code rateLimitRules}）；{@code allowlistExceptions} 为误拦例外（空列表表示无例外）。
 * 两者与其余规则同属一个不可变对象，随版本一起原子发布。</p>
 */
public record RuleSet(List<SecurityRule> securityRules,
                      List<RateLimitRule> rateLimitRules,
                      List<SourceTierRule> tierRules,
                      List<AllowlistException> allowlistExceptions,
                      long version) {

    /**
     * 兼容构造：无分级档位与例外（等价于空列表）。
     */
    public RuleSet(List<SecurityRule> securityRules,
                   List<RateLimitRule> rateLimitRules,
                   long version) {
        this(securityRules, rateLimitRules, List.of(), List.of(), version);
    }
}

package com.github.highcumontoa.trafficshieldjava.model;

import java.util.List;

/**
 * 规则原子更新请求：非 null 的字段表示整表替换，null 表示保持不变。
 *
 * <p>{@code tierRules} 整表替换来源分级档位（传空列表表示关闭分级），
 * {@code allowlistExceptions} 整表替换误拦例外（传空列表表示清空例外）。
 * 四个部分在同一次更新里先整体校验、再一次原子发布。</p>
 */
public record RuleUpdateRequest(List<SecurityRule> securityRules,
                                List<RateLimitRule> rateLimitRules,
                                List<SourceTierRule> tierRules,
                                List<AllowlistException> allowlistExceptions) {

    /**
     * 兼容构造：只更新安全规则与限流规则，分级档位与例外保持不变。
     */
    public RuleUpdateRequest(List<SecurityRule> securityRules,
                             List<RateLimitRule> rateLimitRules) {
        this(securityRules, rateLimitRules, null, null);
    }
}

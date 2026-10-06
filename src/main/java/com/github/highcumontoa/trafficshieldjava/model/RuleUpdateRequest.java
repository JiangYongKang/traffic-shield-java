package com.github.highcumontoa.trafficshieldjava.model;

import java.util.List;

/**
 * 规则原子更新请求：非 null 的字段表示整表替换，null 表示保持不变。
 * 四个部分（安全规则 / 限流规则 / 分级档位 / 误拦例外）各自独立决定是否替换，
 * 校验全部通过后随同一个新版本一次原子生效。
 */
public record RuleUpdateRequest(List<SecurityRule> securityRules,
                                List<RateLimitRule> rateLimitRules,
                                List<QuotaTier> quotaTiers,
                                List<AllowlistException> allowlistExceptions) {

    /**
     * 兼容旧调用方：只更新安全规则与限流规则，档位与例外保持不变。
     */
    public RuleUpdateRequest(List<SecurityRule> securityRules,
                             List<RateLimitRule> rateLimitRules) {
        this(securityRules, rateLimitRules, null, null);
    }
}

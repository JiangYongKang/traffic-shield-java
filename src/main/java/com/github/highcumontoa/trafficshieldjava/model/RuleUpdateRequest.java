package com.github.highcumontoa.trafficshieldjava.model;

import java.util.List;

/**
 * 规则原子更新请求：非 null 的字段表示整表替换，null 表示保持不变。
 */
public record RuleUpdateRequest(List<SecurityRule> securityRules,
                                List<RateLimitRule> rateLimitRules) {
}

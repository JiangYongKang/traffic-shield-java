package com.github.highcumontoa.trafficshieldjava.model;

import java.util.List;

/**
 * 某一时刻生效的完整规则集，整体不可变，原子替换。
 */
public record RuleSet(List<SecurityRule> securityRules,
                      List<RateLimitRule> rateLimitRules,
                      long version) {
}

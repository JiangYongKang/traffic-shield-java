package com.github.highcumontoa.trafficshieldjava.shield.config;

import com.github.highcumontoa.trafficshieldjava.shield.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.shield.model.SecurityRule;
import java.util.List;

/**
 * 一份不可变的完整防护配置：安全规则 + 限流规则。
 * 配置整体作为一个快照原子替换，避免新旧规则混合判定。
 */
public record ShieldConfig(List<SecurityRule> securityRules,
                           List<RateLimitRule> rateLimitRules) {
}

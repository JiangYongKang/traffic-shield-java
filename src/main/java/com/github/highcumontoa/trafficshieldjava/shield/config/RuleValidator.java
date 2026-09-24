package com.github.highcumontoa.trafficshieldjava.shield.config;

import com.github.highcumontoa.trafficshieldjava.shield.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.shield.model.SecurityRule;
import java.util.HashSet;
import java.util.Set;

/**
 * 规则合法性校验：非法规则抛出 {@link InvalidRuleException}，由调用方保证原配置不被替换。
 */
public final class RuleValidator {

    private RuleValidator() {
    }

    public static void validate(ShieldConfig config) {
        if (config == null) {
            throw new InvalidRuleException("配置不能为空");
        }
        if (config.securityRules() == null || config.rateLimitRules() == null) {
            throw new InvalidRuleException("安全规则列表与限流规则列表均不能为 null");
        }

        Set<String> securityIds = new HashSet<>();
        for (SecurityRule rule : config.securityRules()) {
            if (rule == null) {
                throw new InvalidRuleException("安全规则不能为 null 元素");
            }
            if (isBlank(rule.id())) {
                throw new InvalidRuleException("安全规则 id 不能为空");
            }
            if (!securityIds.add(rule.id())) {
                throw new InvalidRuleException("安全规则 id 重复: " + rule.id());
            }
            if (rule.reason() == null) {
                throw new InvalidRuleException("安全规则 " + rule.id() + " 的拒绝原因为空");
            }
            if (rule.pattern() == null) {
                throw new InvalidRuleException("安全规则 " + rule.id() + " 的检测表达式为空");
            }
        }

        Set<String> rateIds = new HashSet<>();
        Set<String> paths = new HashSet<>();
        for (RateLimitRule rule : config.rateLimitRules()) {
            if (rule == null) {
                throw new InvalidRuleException("限流规则不能为 null 元素");
            }
            if (isBlank(rule.id())) {
                throw new InvalidRuleException("限流规则 id 不能为空");
            }
            if (!rateIds.add(rule.id())) {
                throw new InvalidRuleException("限流规则 id 重复: " + rule.id());
            }
            if (isBlank(rule.pathPattern())) {
                throw new InvalidRuleException("限流规则 " + rule.id() + " 的入口路径为空");
            }
            if (!paths.add(rule.pathPattern())) {
                throw new InvalidRuleException("限流入口路径重复: " + rule.pathPattern());
            }
            if (rule.limit() <= 0) {
                throw new InvalidRuleException("限流规则 " + rule.id() + " 的配额必须为正数");
            }
            if (rule.windowMillis() <= 0) {
                throw new InvalidRuleException("限流规则 " + rule.id() + " 的窗口长度必须为正数");
            }
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}

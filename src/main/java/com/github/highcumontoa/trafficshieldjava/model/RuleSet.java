package com.github.highcumontoa.trafficshieldjava.model;

import java.util.List;

/**
 * 某一时刻生效的完整规则集，整体不可变，原子替换。
 *
 * <p>安全规则、限流规则、来源分级配额档位、误拦例外四部分同属一份规则集，
 * 任何一部分的更新都随整份规则集一次性原子生效。</p>
 */
public record RuleSet(List<SecurityRule> securityRules,
                      List<RateLimitRule> rateLimitRules,
                      List<QuotaTier> quotaTiers,
                      List<AllowlistException> allowlistExceptions,
                      long version) {
}

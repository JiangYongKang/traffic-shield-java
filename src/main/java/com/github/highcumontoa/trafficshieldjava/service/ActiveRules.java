package com.github.highcumontoa.trafficshieldjava.service;

import com.github.highcumontoa.trafficshieldjava.model.RuleSet;
import com.github.highcumontoa.trafficshieldjava.security.SecurityInspector;

import java.util.List;

/**
 * 某一时刻生效的完整规则及其编译结果。整体不可变，作为规则更新的唯一发布单位：
 * 一次请求从同一个 {@code ActiveRules} 引用读取安全规则、限流规则、分级档位与误拦例外，
 * 因此更新生效的瞬间不可能出现新旧规则混合判定。
 */
public record ActiveRules(RuleSet set,
                          List<SecurityInspector.CompiledRule> compiledSecurity,
                          List<SecurityInspector.CompiledException> compiledExceptions) {

    /**
     * 兼容构造：无误拦例外。
     */
    public ActiveRules(RuleSet set, List<SecurityInspector.CompiledRule> compiledSecurity) {
        this(set, compiledSecurity, List.of());
    }
}

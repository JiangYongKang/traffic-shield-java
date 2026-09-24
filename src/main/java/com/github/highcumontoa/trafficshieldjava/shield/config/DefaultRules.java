package com.github.highcumontoa.trafficshieldjava.shield.config;

import com.github.highcumontoa.trafficshieldjava.shield.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.shield.model.RejectReason;
import com.github.highcumontoa.trafficshieldjava.shield.model.SecurityRule;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 内置默认规则。
 *
 * <p>规则顺序即检测优先级：异常编码 -&gt; 路径穿越 -&gt; SQL 注入 -&gt; XSS，
 * 命中靠前的规则会先返回，从而保证拒绝原因稳定可区分。</p>
 */
public final class DefaultRules {

    private DefaultRules() {
    }

    public static ShieldConfig defaultConfig() {
        return new ShieldConfig(defaultSecurityRules(), defaultRateLimitRules());
    }

    private static List<SecurityRule> defaultSecurityRules() {
        return List.of(
                // 1. 异常编码：% 后未跟随两个十六进制字符（仅作用于 URL 组件，避免误伤正文中的 "100%" 等文本）
                rule("SEC-ENCODING-001", RejectReason.MALFORMED_ENCODING,
                        "%(?![0-9a-fA-F]{2})", true),
                // 2. 异常编码：空字节
                rule("SEC-ENCODING-002", RejectReason.MALFORMED_ENCODING,
                        "%00|\\x00|\\u0000", true),
                // 3. 路径穿越：../、..\ 或以 .. 结尾（编码形式在检测时先解码）
                rule("SEC-PATH-001", RejectReason.PATH_TRAVERSAL,
                        "\\.\\.(?:[/\\\\]|$)", true),
                // 4. SQL 注入：引号闭合后的恒真/恒假表达式
                rule("SEC-SQLI-001", RejectReason.SQL_INJECTION,
                        "'\\s*(?:or|and)\\s+'?[\\w.]+'?\\s*=\\s*'?[\\w.]+'?", false),
                // 5. SQL 注入：union select
                rule("SEC-SQLI-002", RejectReason.SQL_INJECTION,
                        "\\bunion\\b(?:[\\s/*]|/\\*.*?\\*/)+\\bselect\\b", false),
                // 6. SQL 注入：危险堆叠语句 / 注释结尾
                rule("SEC-SQLI-003", RejectReason.SQL_INJECTION,
                        ";\\s*(?:drop|truncate)\\s+table|(?:--|#)\\s*$", false),
                // 7. SQL 注入：时间盲注 / 元数据查询
                rule("SEC-SQLI-004", RejectReason.SQL_INJECTION,
                        "\\b(?:sleep|benchmark)\\s*\\(|\\bwaitfor\\s+delay\\b|\\binformation_schema\\b", false),
                // 8. XSS：script 标签
                rule("SEC-XSS-001", RejectReason.XSS_ATTEMPT,
                        "<\\s*script(?:[\\s>]|$)", false),
                // 9. XSS：危险标签
                rule("SEC-XSS-002", RejectReason.XSS_ATTEMPT,
                        "<\\s*(?:iframe|img|svg|on\\w+)(?:[\\s>]|$)", false),
                // 10. XSS：事件处理器 / javascript: 协议
                rule("SEC-XSS-003", RejectReason.XSS_ATTEMPT,
                        "\\bon\\w+\\s*=\\s*['\"]?\\s*[\\w.]+\\s*\\(|javascript\\s*:", false)
        );
    }

    private static List<RateLimitRule> defaultRateLimitRules() {
        return List.of(
                new RateLimitRule("RL-HELLO", "/api/hello", 10, 1_000L),
                new RateLimitRule("RL-SUBMIT", "/api/submit", 5, 1_000L)
        );
    }

    private static SecurityRule rule(String id, RejectReason reason, String regex, boolean urlOnly) {
        return new SecurityRule(id, reason, Pattern.compile(regex, Pattern.CASE_INSENSITIVE), urlOnly);
    }
}

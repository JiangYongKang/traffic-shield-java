package com.github.highcumontoa.trafficshieldjava.security;

import com.github.highcumontoa.trafficshieldjava.model.DecisionReason;
import com.github.highcumontoa.trafficshieldjava.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.model.SecurityRule;

import java.util.List;

/**
 * 内置默认规则。签名均取明显的攻击惯用片段，尽量避免误拦正常业务文本；
 * 异常编码类规则由 {@link SecurityInspector} 内置检查（ENC-*），不在此处。
 */
public final class DefaultRules {

    private DefaultRules() {
    }

    public static List<SecurityRule> securityRules() {
        return List.of(
                // ---- SQL 注入 ----
                // 仅匹配明确的 SQL 行注释：-- 后空白/结尾、# 后空白/结尾；
                // 不单独拦 "/*"，避免把 Accept: */* 这类正常头误判（块注释须带 SELECT 等关键词）
                rule("SQL-001", "SQL 注释符", DecisionReason.SQL_INJECTION,
                        "(?:--[ \\t]|--$|#[ \\t]|/\\*\\s*(?:select|union|or|and)\\b)"),
                rule("SQL-002", "UNION 注入", DecisionReason.SQL_INJECTION,
                        "union\\s+(?:all\\s+)?select\\b"),
                rule("SQL-003", "堆叠/布尔注入", DecisionReason.SQL_INJECTION,
                        ";\\s*(?:drop|insert|update|delete|select)\\b|\\bor\\s+1\\s*=\\s*1\\b"),
                rule("SQL-004", "条件恒真与注释闭合", DecisionReason.SQL_INJECTION,
                        "'\\s*or\\s*'?\\d*'?\\s*=\\s*'?\\d*|'\\s*--"),
                rule("SQL-005", "危险 SQL 关键字组合", DecisionReason.SQL_INJECTION,
                        "\\b(?:drop\\s+table|delete\\s+from|insert\\s+into|information_schema|sleep\\s*\\(|waitfor\\s+delay)"),

                // ---- XSS ----
                rule("XSS-001", "脚本标签", DecisionReason.XSS,
                        "<\\s*script\\b|</\\s*script\\s*>"),
                rule("XSS-002", "事件属性注入", DecisionReason.XSS,
                        "\\bon[a-z]+\\s*="),
                rule("XSS-003", "javascript/data 协议", DecisionReason.XSS,
                        "(?:javascript|data)\\s*:"),
                rule("XSS-004", "标签注入", DecisionReason.XSS,
                        "<\\s*(?:iframe|img|svg|object|embed)\\b"),

                // ---- 命令注入 ----
                rule("CMD-001", "Shell 命令连接符", DecisionReason.COMMAND_INJECTION,
                        "[;&|`]\\s*(?:ls|cat|id|whoami|wget|curl|bash|sh|nc|ping|uname|rm)\\b"),
                rule("CMD-002", "命令替换", DecisionReason.COMMAND_INJECTION,
                        "\\$\\(\\s*(?:ls|cat|id|whoami|wget|curl|bash|sh|nc|ping|uname|rm)\\b"),
                rule("CMD-003", "危险命令名组合", DecisionReason.COMMAND_INJECTION,
                        "\\b(?:cat\\s+/etc/passwd|/bin/sh|/bin/bash|cmd\\.exe|powershell)\\b"),

                // ---- 路径穿越 ----
                rule("PATH-001", "上级目录穿越", DecisionReason.PATH_TRAVERSAL,
                        "\\.\\.[/\\\\]|[/\\\\]\\.\\."),
                rule("PATH-002", "敏感系统路径", DecisionReason.PATH_TRAVERSAL,
                        "(?:/etc/passwd|/etc/shadow|boot\\.ini|win\\.ini|\\.ssh/(?:id_rsa|authorized_keys))"),

                // ---- 可疑编码（签名型；畸形编码另有 ENC-* 内置检查）----
                rule("ENC-SQL-HEX", "十六进制编码的 SQL 特征", DecisionReason.SUSPICIOUS_ENCODING,
                        "0x[0-9a-f]{8,}"),
                rule("ENC-CHAR-CONCAT", "CHAR 拼接绕过", DecisionReason.SUSPICIOUS_ENCODING,
                        "\\bchar\\s*\\(\\s*\\d+\\s*(?:,\\s*\\d+\\s*)+\\)"),
                rule("ENC-CSS-ESCAPE", "CSS 表达式/反引号转义绕过", DecisionReason.SUSPICIOUS_ENCODING,
                        "\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}")
        );
    }

    /**
     * 默认限流规则：所有路径、每来源每窗口 defaultLimit 次。
     */
    public static RateLimitRule defaultRateLimitRule(int limit, int windowSeconds) {
        return new RateLimitRule("RL-DEFAULT", "/**", limit, windowSeconds);
    }

    private static SecurityRule rule(String id, String name, DecisionReason reason, String pattern) {
        return new SecurityRule(id, name, reason.name(), pattern);
    }
}

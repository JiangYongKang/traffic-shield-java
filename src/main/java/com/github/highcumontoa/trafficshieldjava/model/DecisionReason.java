package com.github.highcumontoa.trafficshieldjava.model;

/**
 * 防护判定原因。每个原因码稳定不变，用于向调用方解释结论。
 */
public enum DecisionReason {
    ALLOWED,
    SQL_INJECTION,
    XSS,
    COMMAND_INJECTION,
    PATH_TRAVERSAL,
    SUSPICIOUS_ENCODING,
    RATE_LIMITED
}

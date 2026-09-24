package com.github.highcumontoa.trafficshieldjava.shield.model;

/**
 * 稳定且可区分的拒绝原因。
 */
public enum RejectReason {
    MALFORMED_ENCODING,
    PATH_TRAVERSAL,
    SQL_INJECTION,
    XSS_ATTEMPT,
    RATE_LIMITED
}

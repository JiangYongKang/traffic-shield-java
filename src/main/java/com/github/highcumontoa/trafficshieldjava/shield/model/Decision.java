package com.github.highcumontoa.trafficshieldjava.shield.model;

/**
 * 对一次入站请求的总体判定。
 */
public enum Decision {
    ALLOW,
    REJECT_SECURITY,
    REJECT_RATE_LIMIT
}

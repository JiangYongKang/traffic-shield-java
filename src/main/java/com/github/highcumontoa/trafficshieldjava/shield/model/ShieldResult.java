package com.github.highcumontoa.trafficshieldjava.shield.model;

/**
 * 一次防护判定的结论，含可解释依据。
 */
public record ShieldResult(Decision decision,
                           RejectReason reason,
                           String ruleId,
                           String evidence,
                           long retryAfterMillis) {
}

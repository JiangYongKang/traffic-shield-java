package com.github.highcumontoa.trafficshieldjava.shield.config;

/**
 * 规则非法时抛出，调用方应保留原有规则。
 */
public class InvalidRuleException extends RuntimeException {
    public InvalidRuleException(String message) {
        super(message);
    }
}

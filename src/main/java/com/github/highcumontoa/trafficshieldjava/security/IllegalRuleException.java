package com.github.highcumontoa.trafficshieldjava.security;

/**
 * 规则校验失败时抛出；更新操作在替换生效前抛出，旧规则保持不变。
 */
public class IllegalRuleException extends RuntimeException {
    public IllegalRuleException(String message) {
        super(message);
    }
}

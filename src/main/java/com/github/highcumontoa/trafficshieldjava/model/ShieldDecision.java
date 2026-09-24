package com.github.highcumontoa.trafficshieldjava.model;

/**
 * 防护层对一次请求给出的最终判定结论。
 * <p>结论对象不可变，包含稳定的原因码、命中规则与可解释信息；
 * 被限流时 {@link #retryAfterSeconds()} 非空，用于可重试提示。
 *
 * @param allowed           是否放行
 * @param reason            稳定的判定原因码
 * @param ruleId            命中的规则标识（放行时为 null）
 * @param message           人类可读的判定依据
 * @param retryAfterSeconds 仅限流场景：建议多少秒后重试（否则为 null）
 * @param rulesVersion      判定时生效的规则版本
 * @param source            请求来源
 * @param path              请求路径（便于日志与响应自解释）
 */
public record ShieldDecision(boolean allowed,
                             DecisionReason reason,
                             String ruleId,
                             String message,
                             Long retryAfterSeconds,
                             long rulesVersion,
                             String source,
                             String path) {

    /**
     * 构造一个放行结论。
     */
    public static ShieldDecision allow(long rulesVersion, String source, String path) {
        return new ShieldDecision(true, DecisionReason.ALLOWED, null,
                "请求未命中任何安全规则且未超过限流阈值", null,
                rulesVersion, source, path);
    }

    /**
     * 构造一个安全拒绝结论。
     */
    public static ShieldDecision reject(DecisionReason reason, String ruleId,
                                        String message, long rulesVersion,
                                        String source, String path) {
        return new ShieldDecision(false, reason, ruleId, message, null,
                rulesVersion, source, path);
    }

    /**
     * 构造一个限流拒绝结论。
     */
    public static ShieldDecision rateLimited(String ruleId, long retryAfterSeconds,
                                             long rulesVersion, String source,
                                             String path) {
        return new ShieldDecision(false, DecisionReason.RATE_LIMITED, ruleId,
                "请求已超过来源 [" + source + "] 在规则 [" + ruleId + "] 下的时间窗口配额",
                retryAfterSeconds, rulesVersion, source, path);
    }
}

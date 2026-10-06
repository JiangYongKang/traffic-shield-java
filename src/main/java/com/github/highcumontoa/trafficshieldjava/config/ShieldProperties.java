package com.github.highcumontoa.trafficshieldjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 防护层可配置项，前缀 {@code traffic-shield}。
 *
 * <ul>
 *   <li>{@code enabled}：安全检测总开关，关闭后跳过安全规则匹配；</li>
 *   <li>{@code default-limit} / {@code default-window-seconds}：
 *       内置默认限流规则（匹配所有路径）的每窗口配额与窗口长度；</li>
 *   <li>{@code source-header}：从哪个请求头识别来源（取第一个值），
 *       缺省回退到对端地址，JSON 入口可显式传 source；</li>
 *   <li>{@code sweep-interval-seconds}：限流过期窗口的清理间隔；</li>
 *   <li>{@code max-state-entries}：限流器保留的状态条目（计数窗口+回收影子）上限，
 *       超限时按回收策略释放，防止高基数来源撑爆内存。</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "traffic-shield")
public class ShieldProperties {

    private boolean enabled = true;
    private int defaultLimit = 10;
    private int defaultWindowSeconds = 10;
    private String sourceHeader = "X-Forwarded-For";
    private long sweepIntervalSeconds = 10;
    private int maxStateEntries = 10_000;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getDefaultLimit() {
        return defaultLimit;
    }

    public void setDefaultLimit(int defaultLimit) {
        this.defaultLimit = defaultLimit;
    }

    public int getDefaultWindowSeconds() {
        return defaultWindowSeconds;
    }

    public void setDefaultWindowSeconds(int defaultWindowSeconds) {
        this.defaultWindowSeconds = defaultWindowSeconds;
    }

    public String getSourceHeader() {
        return sourceHeader;
    }

    public void setSourceHeader(String sourceHeader) {
        this.sourceHeader = sourceHeader;
    }

    public long getSweepIntervalSeconds() {
        return sweepIntervalSeconds;
    }

    public void setSweepIntervalSeconds(long sweepIntervalSeconds) {
        this.sweepIntervalSeconds = sweepIntervalSeconds;
    }

    public int getMaxStateEntries() {
        return maxStateEntries;
    }

    public void setMaxStateEntries(int maxStateEntries) {
        this.maxStateEntries = maxStateEntries;
    }
}

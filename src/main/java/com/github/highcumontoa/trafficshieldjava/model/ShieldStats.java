package com.github.highcumontoa.trafficshieldjava.model;

import java.util.Map;

/**
 * 某一时刻的防护统计快照（不可变，查询时在同一把读锁下生成，字段间自洽）。
 *
 * @param rulesVersion      快照对应的规则版本
 * @param total             进入防护层的请求总数
 * @param allowed           放行总数
 * @param securityRejected  各安全拒绝原因码 -> 次数
 * @param rateLimited       限流拒绝总数
 */
public record ShieldStats(long rulesVersion,
                          long total,
                          long allowed,
                          Map<String, Long> securityRejected,
                          long rateLimited) {

    /**
     * 生成一个初始空快照。
     */
    public static ShieldStats empty(long rulesVersion) {
        return new ShieldStats(rulesVersion, 0, 0, Map.of(), 0);
    }
}

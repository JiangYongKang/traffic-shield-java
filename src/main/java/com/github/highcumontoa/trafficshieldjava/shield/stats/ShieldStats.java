package com.github.highcumontoa.trafficshieldjava.shield.stats;

import com.github.highcumontoa.trafficshieldjava.shield.model.RejectReason;
import java.util.EnumMap;
import java.util.Map;

/**
 * 命中 / 拒绝 / 限流统计。
 *
 * <p>所有记录与快照读取都在同一把锁上进行，保证 total 与各分项、
 * 以及按原因拆分的明细在同一时刻相互自洽。</p>
 */
public class ShieldStats {

    private long total;
    private long allowed;
    private long rejected;
    private long rateLimited;
    private final EnumMap<RejectReason, Long> rejectedByReason = new EnumMap<>(RejectReason.class);

    public synchronized void recordAllowed() {
        total++;
        allowed++;
    }

    public synchronized void recordRejected(RejectReason reason) {
        total++;
        rejected++;
        rejectedByReason.merge(reason, 1L, Long::sum);
    }

    public synchronized void recordRateLimited() {
        total++;
        rateLimited++;
        rejectedByReason.merge(RejectReason.RATE_LIMITED, 1L, Long::sum);
    }

    public synchronized StatsSnapshot snapshot() {
        EnumMap<RejectReason, Long> copy = new EnumMap<>(RejectReason.class);
        for (Map.Entry<RejectReason, Long> entry : rejectedByReason.entrySet()) {
            copy.put(entry.getKey(), entry.getValue());
        }
        return new StatsSnapshot(total, allowed, rejected, rateLimited, copy);
    }
}

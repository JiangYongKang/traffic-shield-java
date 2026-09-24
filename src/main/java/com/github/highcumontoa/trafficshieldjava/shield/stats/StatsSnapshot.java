package com.github.highcumontoa.trafficshieldjava.shield.stats;

import com.github.highcumontoa.trafficshieldjava.shield.model.RejectReason;
import java.util.Map;

/**
 * 统计的一致快照。
 */
public record StatsSnapshot(long total,
                            long allowed,
                            long rejected,
                            long rateLimited,
                            Map<RejectReason, Long> rejectedByReason) {
}

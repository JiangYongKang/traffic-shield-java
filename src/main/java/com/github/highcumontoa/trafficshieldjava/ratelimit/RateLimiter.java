package com.github.highcumontoa.trafficshieldjava.ratelimit;

import com.github.highcumontoa.trafficshieldjava.model.RateLimitRule;
import com.github.highcumontoa.trafficshieldjava.model.SourceTierRule;
import org.springframework.util.AntPathMatcher;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 按来源计数的固定时间窗口限流器，支持来源分级档位与状态容量治理。
 *
 * <p>限流语义：每个 (来源, 规则/档位) 各自维护一个固定窗口，窗口内第 1..limit 个请求放行，
 * 第 limit+1 个起拒绝，直到当前窗口结束后下一个请求开启新窗口。窗口严格按真实时间轮换，
 * 不会提前解除限制。配置了分级档位时，按档位声明顺序取首个 来源+路径 同时命中的档位，
 * 一个请求只按该档位计一次数，不同档位互不影响；未命中任何档位则回退普通限流规则。</p>
 *
 * <p>并发正确性：每个窗口的计数由 {@link AtomicLong} 承担，自增即计数（不回滚），
 * 前 limit 个自增必定放行、之后必定拒绝；窗口切换用 CAS 替换窗口对象，竞争失败者取最新窗口重试；
 * 窗口的创建/恢复通过 {@link ConcurrentHashMap#compute} 与回收串行化，不会丢窗口。</p>
 *
 * <p>容量治理：保留的窗口状态数量上限为 {@code maxEntries}。超限或定时清理时先删除已过期窗口；
 * 仍超限则按"最久未使用"（LRU）回收活跃窗口。被回收的活跃窗口不直接丢弃，而是整体移入
 * 墓碑区（同一 {@code Window} 对象，计数原样保留）：该来源在窗口仍有效期间再次出现时，
 * 通过 compute 原子地恢复原窗口继续计数，<b>同一有效窗口内不会因回收而多放行</b>；
 * 窗口已自然过期的墓碑不参与恢复，由清理直接移除。墓碑区同样以上限约束，超出时先清过期、
 * 再淘汰最旧。回收与正常判定可并发执行，双方只使用并发容器的原子操作，不会向用户抛出异常。</p>
 */
public class RateLimiter {

    /** 默认状态容量上限（窗口数）。 */
    public static final int DEFAULT_MAX_ENTRIES = 10_000;

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /** key = 来源 + '|' + 规则id（档位为 来源 + "|tier:" + 档位id） -> 活跃窗口 */
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    /** 墓碑区：被容量回收但窗口可能仍有效的窗口对象（同一对象，计数不丢）。 */
    private final ConcurrentHashMap<String, Window> evicted = new ConcurrentHashMap<>();

    private final int maxEntries;

    public RateLimiter() {
        this(DEFAULT_MAX_ENTRIES);
    }

    public RateLimiter(int maxEntries) {
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries 必须为正整数");
        }
        this.maxEntries = maxEntries;
    }

    /**
     * 尝试获取一个配额（无分级档位的兼容入口，等价于 tiers 为空）。
     */
    public Denied tryAcquire(List<RateLimitRule> rules, String source, String path, long nowMs) {
        return tryAcquire(List.of(), rules, source, path, nowMs);
    }

    /**
     * 尝试获取一个配额。
     *
     * @param tiers  来源分级档位快照（与规则同属一次原子发布；空列表表示未启用分级）
     * @param rules  普通限流规则快照（未命中任何档位时的回退）
     * @param source 请求来源
     * @param path   请求路径
     * @param nowMs  当前时间（毫秒）
     * @return 放行返回 null；限流返回拒绝信息
     */
    public Denied tryAcquire(List<SourceTierRule> tiers, List<RateLimitRule> rules,
                             String source, String path, long nowMs) {
        String safePath = path == null ? "/" : path;
        // 1) 分级档位优先：首个 来源+路径 同时命中的档位，只计这一次
        if (tiers != null) {
            for (SourceTierRule tier : tiers) {
                if (pathMatcher.match(tier.sourcePattern(), source)
                        && pathMatcher.match(tier.pathPattern(), safePath)) {
                    return acquire(source + "|tier:" + tier.id(),
                            tier.id(), tier.limit(), tier.windowSeconds(), nowMs);
                }
            }
        }
        // 2) 回退普通限流规则：每条匹配的规则各自计数
        if (rules != null) {
            for (RateLimitRule rule : rules) {
                if (!pathMatcher.match(rule.pathPattern(), safePath)) {
                    continue;
                }
                Denied d = acquire(source + "|" + rule.id(),
                        rule.id(), rule.limit(), rule.windowSeconds(), nowMs);
                if (d != null) {
                    return d;
                }
            }
        }
        return null;
    }

    /**
     * 在指定 key 的窗口上计一次数。
     */
    private Denied acquire(String key, String ruleId, int limit, int windowSeconds, long nowMs) {
        long windowLenMs = windowSeconds * 1000L;
        Window window = null;
        while (true) {
            if (window == null) {
                // 创建与墓碑恢复、容量回收都串行在同一个 key 的 compute 上：
                // 要么拿到活跃窗口，要么原子地取回墓碑窗口（窗口仍有效时），要么新建
                window = windows.compute(key, (k, existing) -> {
                    if (existing != null) {
                        return existing;
                    }
                    Window restored = evicted.remove(k);
                    if (restored != null && nowMs - restored.startMs < restored.lengthMs) {
                        return restored; // 同一有效窗口：恢复原计数，不多放行
                    }
                    return new Window(nowMs, windowLenMs);
                });
            }
            // 窗口已过期：CAS 轮换到新窗口；竞争失败则使用别人建好的窗口重试；
            // 若窗口恰被回收（get 为 null），下一轮循环重建
            if (nowMs - window.startMs >= window.lengthMs) {
                Window fresh = new Window(nowMs, windowLenMs);
                if (windows.replace(key, window, fresh)) {
                    window = fresh;
                } else {
                    window = windows.get(key);
                }
                continue;
            }
            window.lastAccessMs.set(nowMs);
            long next = window.current.incrementAndGet();
            maybeEvict(nowMs);
            if (next <= limit) {
                return null; // 获得配额
            }
            long retryAfterMs = window.startMs + window.lengthMs - nowMs;
            long retryAfterSeconds = Math.max(1L, (retryAfterMs + 999L) / 1000L);
            return new Denied(ruleId, limit, windowSeconds,
                    retryAfterSeconds, window.startMs + window.lengthMs);
        }
    }

    /**
     * 清理过期状态并执行容量回收（由调度任务调用；与正常判定并发安全）。
     */
    public void sweepExpired(long nowMs) {
        removeExpired(windows, nowMs);
        removeExpired(evicted, nowMs);
        enforceCapacity(nowMs);
    }

    /**
     * 状态总量超限时内联触发回收（每次判定仅一次 size 检查，未超限零开销）。
     */
    private void maybeEvict(long nowMs) {
        if (windows.size() > maxEntries) {
            enforceCapacity(nowMs);
        }
    }

    /**
     * 容量回收：先清过期窗口；仍超限则按 LRU 把最久未使用的活跃窗口整体移入墓碑区
     * （计数随对象保留，窗口仍有效时可被原样恢复）。墓碑区同样受容量约束。
     */
    private void enforceCapacity(long nowMs) {
        if (windows.size() > maxEntries) {
            removeExpired(windows, nowMs);
        }
        int overflow = windows.size() - maxEntries;
        if (overflow > 0) {
            List<Map.Entry<String, Window>> live = new ArrayList<>(windows.entrySet());
            live.sort(Comparator.comparingLong(e -> e.getValue().lastAccessMs.get()));
            for (Map.Entry<String, Window> e : live) {
                if (overflow <= 0) {
                    break;
                }
                // computeIfPresent 与判定路径上的 compute 按 key 串行：
                // 移入墓碑区与从 windows 移除是同一回调，不会出现窗口既丢计数又新建的空档
                boolean[] moved = {false};
                windows.computeIfPresent(e.getKey(), (k, w) -> {
                    if (w == e.getValue()) {
                        evicted.put(k, w);
                        moved[0] = true;
                        return null;
                    }
                    return w;
                });
                if (moved[0]) {
                    overflow--;
                }
            }
        }
        // 墓碑区容量治理：先清过期，仍超限则淘汰最旧（其窗口多已结束，影响最小）
        if (evicted.size() > maxEntries) {
            removeExpired(evicted, nowMs);
        }
        int tombOverflow = evicted.size() - maxEntries;
        if (tombOverflow > 0) {
            List<Map.Entry<String, Window>> tombs = new ArrayList<>(evicted.entrySet());
            tombs.sort(Comparator.comparingLong(e -> e.getValue().startMs));
            for (Map.Entry<String, Window> e : tombs) {
                if (tombOverflow <= 0) {
                    break;
                }
                if (evicted.remove(e.getKey(), e.getValue())) {
                    tombOverflow--;
                }
            }
        }
    }

    private static void removeExpired(ConcurrentHashMap<String, Window> map, long nowMs) {
        for (Iterator<Map.Entry<String, Window>> it = map.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, Window> e = it.next();
            Window w = e.getValue();
            if (nowMs - w.startMs > w.lengthMs) {
                map.remove(e.getKey(), w);
            }
        }
    }

    /**
     * 仅用于测试/诊断：查看某来源在某规则上的当前窗口计数（可能在窗口边界瞬间变化）。
     */
    public long currentCount(String source, String ruleId, long nowMs) {
        return countOf(source + "|" + ruleId, nowMs);
    }

    /**
     * 仅用于测试/诊断：查看某来源在某档位上的当前窗口计数。
     */
    public long currentTierCount(String source, String tierId, long nowMs) {
        return countOf(source + "|tier:" + tierId, nowMs);
    }

    private long countOf(String key, long nowMs) {
        Window w = windows.get(key);
        if (w == null) {
            w = evicted.get(key);
        }
        if (w == null || nowMs - w.startMs >= w.lengthMs) {
            return 0L;
        }
        return w.current.get();
    }

    /**
     * 仅用于测试/诊断：当前保留的活跃窗口数与墓碑窗口数。
     */
    public int activeWindowCount() {
        return windows.size();
    }

    public int evictedWindowCount() {
        return evicted.size();
    }

    /**
     * 一个固定计数窗口。
     */
    private static final class Window {
        private final long startMs;
        private final long lengthMs;
        private final AtomicLong current = new AtomicLong(0);
        /** 最近一次命中时间，LRU 回收依据。 */
        private final AtomicLong lastAccessMs;

        private Window(long startMs, long lengthMs) {
            this.startMs = startMs;
            this.lengthMs = lengthMs;
            this.lastAccessMs = new AtomicLong(startMs);
        }
    }

    /**
     * 限流拒绝信息。
     */
    public record Denied(String ruleId, int limit, int windowSeconds,
                         long retryAfterSeconds, long windowResetMs) {
    }
}

package com.github.highcumontoa.trafficshieldjava.ratelimit;

import com.github.highcumontoa.trafficshieldjava.model.QuotaTier;
import com.github.highcumontoa.trafficshieldjava.model.RateLimitRule;
import org.springframework.util.AntPathMatcher;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 按来源与规则/档位计数的固定时间窗口限流器。
 *
 * <p>语义：每个 (来源, 限流规则) 与每个 (来源, 配额档位) 各自维护一个固定窗口，
 * 窗口内第 1..limit 个请求放行，第 limit+1 个起拒绝，直到当前窗口结束后下一个请求开启新窗口。
 * 窗口严格按真实时间轮换，不会提前解除限制。</p>
 *
 * <p>并发正确性：每个窗口的计数由 {@link AtomicLong} 承担，自增即计数（不回滚），
 * 前 limit 个自增必定放行、之后必定拒绝，保证突发与并发下不丢计数、不重复放行；
 * 窗口轮换、影子恢复都在 {@link ConcurrentHashMap#compute} 内按 key 原子完成，
 * 不存在新旧窗口混用。</p>
 *
 * <p>状态容量治理：状态分两类，<strong>各自</strong>不超过 {@code maxStateEntries}
 * （即总预算为 2 倍上限，上限语义明确）：</p>
 * <ul>
 *   <li>存活窗口：正在接受计数的窗口；</li>
 *   <li>回收影子：被回收的存活窗口留下的只读计数记录（窗口边界 + 已计数值）。</li>
 * </ul>
 * <p>超限时的回收策略（严格按序）：</p>
 * <ol>
 *   <li>先删除窗口已经结束的过期条目（两类都删）；</li>
 *   <li>存活窗口仍超限，则把窗口开始时间最早的存活窗口降级为影子
 *       （存活窗口只降级、绝不直接硬删，因此计数不丢）；</li>
 *   <li>影子空间不足时，先删过期影子，再按开始时间最早优先硬删影子。
 *       只有走到这一步，对应来源的窗口计数才真正丢失。</li>
 * </ol>
 *
 * <p>配额连续性：被降级为影子的来源在<strong>同一个仍有效的窗口</strong>内再次出现时，
 * 从影子恢复原窗口继续计数（降级/恢复共享同一个 {@link AtomicLong}，只是对象在两张表间移动，
 * 计数器本身不变），因此不会因为状态被回收而在同一窗口内凭空多获得配额；
 * 窗口结束后影子随过期清理一并删除，来源按新窗口重新计数。
 * 只有在影子预算也被占满的极端压力下，来源才按新窗口处理（宁可放行也不让内存失控），
 * 这是容量保护语义中明确记录的取舍。</p>
 *
 * <p>清理与判定并发：回收只使用条件删除/条件替换（remove(key, value) 等），
 * 与正常判定并发执行不会抛错；判定侧持有的窗口对象即使被降级，其计数仍落在共享计数器上，
 * 最终放行/拒绝结论只取决于计数器与阈值的比较，不会前后矛盾。</p>
 */
public class RateLimiter {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /** 容量上限：存活窗口与回收影子各自不超过该值。 */
    private final int maxStateEntries;

    /** 存活窗口：key = 来源 + '|' + 规则id（或 'TIER:' + 档位id） */
    private final ConcurrentHashMap<String, Entry> windows = new ConcurrentHashMap<>();

    /** 回收影子：被降级窗口的只读计数记录，key 与存活窗口相同 */
    private final ConcurrentHashMap<String, Entry> shadows = new ConcurrentHashMap<>();

    public RateLimiter() {
        this(10_000);
    }

    public RateLimiter(int maxStateEntries) {
        if (maxStateEntries <= 0) {
            throw new IllegalArgumentException("maxStateEntries 必须为正整数");
        }
        this.maxStateEntries = maxStateEntries;
    }

    /**
     * 尝试获取一个配额。
     *
     * @param rules  本次判定使用的限流规则快照（与安全规则同属一次原子发布）
     * @param source 请求来源
     * @param path   请求路径，用于选择匹配的限流规则
     * @param nowMs  当前时间（毫秒）
     * @return 放行返回 null；限流返回拒绝信息
     */
    public Denied tryAcquire(List<RateLimitRule> rules, String source, String path, long nowMs) {
        for (RateLimitRule rule : rules) {
            if (!pathMatcher.match(rule.pathPattern(), path == null ? "/" : path)) {
                continue;
            }
            Denied denied = acquire(source + "|" + rule.id(), rule.id(),
                    rule.limit(), rule.windowSeconds(), nowMs);
            if (denied != null) {
                return denied;
            }
        }
        return null;
    }

    /**
     * 按来源分级档位尝试获取一个配额。档位窗口与规则窗口互相独立、互不影响。
     *
     * @param tier   请求命中的档位（调用方负责按档位表顺序解析，首个命中即唯一计数档）
     * @param source 请求来源
     * @param nowMs  当前时间（毫秒）
     * @return 放行返回 null；限流返回拒绝信息（ruleId 为档位 id）
     */
    public Denied tryAcquireTier(QuotaTier tier, String source, long nowMs) {
        return acquire(source + "|TIER:" + tier.id(), tier.id(),
                tier.limit(), tier.windowSeconds(), nowMs);
    }

    /**
     * 核心计数：取（或建/恢复）该 key 的当前窗口并自增计数，按阈值给出放行/拒绝。
     */
    private Denied acquire(String key, String ruleId, int limit, int windowSeconds, long nowMs) {
        long windowMs = windowSeconds * 1000L;
        // compute 按 key 原子执行：过期轮换、影子恢复、新建窗口三者不会交错
        Entry entry = windows.compute(key, (k, old) -> {
            if (old != null && nowMs - old.startMs < old.lengthMs) {
                return old; // 存活窗口未过期，继续计数
            }
            // 窗口不存在或已过期：先看影子里有没有仍有效的同一窗口
            Entry shadow = shadows.remove(k);
            if (shadow != null && nowMs - shadow.startMs < shadow.lengthMs) {
                return shadow; // 恢复影子：同一窗口继续计数，不重置
            }
            return new Entry(nowMs, windowMs);
        });
        // 可能新增了条目，检查容量并按策略回收（与并发判定安全共存）
        enforceCapacity(nowMs);

        long next = entry.current.incrementAndGet();
        if (next <= limit) {
            return null; // 获得配额
        }
        long retryAfterMs = entry.startMs + entry.lengthMs - nowMs;
        long retryAfterSeconds = Math.max(1L, (retryAfterMs + 999L) / 1000L);
        return new Denied(ruleId, limit, windowSeconds,
                retryAfterSeconds, entry.startMs + entry.lengthMs);
    }

    /**
     * 容量治理：存活窗口超过上限时按既定策略回收。
     * 只使用条件删除/条件替换，与并发判定共存不会产生异常或矛盾结论。
     */
    private void enforceCapacity(long nowMs) {
        if (windows.size() <= maxStateEntries && shadows.size() <= maxStateEntries) {
            return;
        }
        // 1) 先回收两类中已经过期的条目
        removeExpired(windows, nowMs);
        removeExpired(shadows, nowMs);
        // 2) 存活窗口仍超限：把开始时间最早的存活窗口降级为影子（计数保留）
        while (windows.size() > maxStateEntries) {
            String oldestKey = findOldestKey(windows);
            if (oldestKey == null) {
                break;
            }
            Entry oldest = windows.get(oldestKey);
            if (oldest == null || !windows.remove(oldestKey, oldest)) {
                continue; // 并发修改，重扫
            }
            ensureShadowSpace(nowMs);
            shadows.put(oldestKey, oldest);
        }
    }

    /** 为新的影子腾出空间：先删过期影子，仍满则硬删开始时间最早的影子。 */
    private void ensureShadowSpace(long nowMs) {
        if (shadows.size() < maxStateEntries) {
            return;
        }
        removeExpired(shadows, nowMs);
        while (shadows.size() >= maxStateEntries) {
            String oldestKey = findOldestKey(shadows);
            if (oldestKey == null) {
                break;
            }
            Entry oldest = shadows.get(oldestKey);
            if (oldest == null || !shadows.remove(oldestKey, oldest)) {
                break; // 并发修改，放弃本次腾挪（下一次回收再处理）
            }
        }
    }

    private static void removeExpired(ConcurrentHashMap<String, Entry> map, long nowMs) {
        for (Iterator<Map.Entry<String, Entry>> it = map.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, Entry> e = it.next();
            Entry w = e.getValue();
            if (nowMs - w.startMs > w.lengthMs) {
                map.remove(e.getKey(), w);
            }
        }
    }

    private static String findOldestKey(ConcurrentHashMap<String, Entry> map) {
        String oldestKey = null;
        long oldestStart = Long.MAX_VALUE;
        for (Map.Entry<String, Entry> e : map.entrySet()) {
            if (e.getValue().startMs < oldestStart) {
                oldestStart = e.getValue().startMs;
                oldestKey = e.getKey();
            }
        }
        return oldestKey;
    }

    /**
     * 清理已经结束的窗口与影子，避免内存无限增长。仅删除确认过期且未被轮换的条目。
     */
    public void sweepExpired(long nowMs) {
        removeExpired(windows, nowMs);
        removeExpired(shadows, nowMs);
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
        return countOf(source + "|TIER:" + tierId, nowMs);
    }

    private long countOf(String key, long nowMs) {
        Entry w = windows.get(key);
        if (w == null) {
            w = shadows.get(key);
        }
        if (w == null || nowMs - w.startMs >= w.lengthMs) {
            return 0L;
        }
        return w.current.get();
    }

    /**
     * 仅用于测试/诊断：当前保留的状态条目总数（存活窗口 + 回收影子）。
     * 存活窗口与影子各自不超过容量上限，因此总数不超过 2 倍上限。
     */
    public int stateSize() {
        return windows.size() + shadows.size();
    }

    /**
     * 仅用于测试/诊断：当前存活窗口数（不超过容量上限）。
     */
    public int liveWindowCount() {
        return windows.size();
    }

    /**
     * 一个状态条目：存活窗口或其回收影子。对象不可变（计数器除外），
     * 降级/恢复只是同一个对象在两张表之间移动，计数器始终不变，
     * 因此计数在状态转换间不丢失。
     */
    private static final class Entry {
        private final long startMs;
        private final long lengthMs;
        private final AtomicLong current = new AtomicLong(0);

        private Entry(long startMs, long lengthMs) {
            this.startMs = startMs;
            this.lengthMs = lengthMs;
        }
    }

    /**
     * 限流拒绝信息。
     */
    public record Denied(String ruleId, int limit, int windowSeconds,
                         long retryAfterSeconds, long windowResetMs) {
    }
}

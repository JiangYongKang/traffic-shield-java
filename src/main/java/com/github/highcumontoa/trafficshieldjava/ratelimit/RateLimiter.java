package com.github.highcumontoa.trafficshieldjava.ratelimit;

import com.github.highcumontoa.trafficshieldjava.model.RateLimitRule;
import org.springframework.util.AntPathMatcher;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 按来源与规则计数的固定时间窗口限流器。
 *
 * <p>语义：每个 (来源, 限流规则) 各自维护一个固定窗口，窗口内第 1..limit 个请求放行，
 * 第 limit+1 个起拒绝，直到当前窗口结束后下一个请求开启新窗口。窗口严格按真实时间轮换，
 * 不会提前解除限制。</p>
 *
 * <p>并发正确性：每个窗口的计数由 {@link AtomicLong} 承担，自增即计数（不回滚），
 * 前 limit 个自增必定放行、之后必定拒绝，保证突发与并发下不丢计数、不重复放行；
 * 窗口切换用 CAS 替换窗口对象，竞争失败者取最新窗口重试。</p>
 */
public class RateLimiter {

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /** key = 来源 + '|' + 规则id -> 窗口对象 */
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

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
            String key = source + "|" + rule.id();
            Window window = windows.computeIfAbsent(key,
                    k -> new Window(nowMs, rule.windowSeconds() * 1000L));
            while (true) {
                // 窗口已过期：CAS 轮换到新窗口；竞争失败则使用别人建好的窗口重试
                if (nowMs - window.startMs >= window.lengthMs) {
                    Window fresh = new Window(nowMs, rule.windowSeconds() * 1000L);
                    if (windows.replace(key, window, fresh)) {
                        window = fresh;
                    } else {
                        window = windows.get(key);
                    }
                    continue;
                }
                long next = window.current.incrementAndGet();
                if (next <= rule.limit()) {
                    return null; // 获得配额
                }
                long retryAfterMs = window.startMs + window.lengthMs - nowMs;
                long retryAfterSeconds = Math.max(1L, (retryAfterMs + 999L) / 1000L);
                return new Denied(rule.id(), rule.limit(), rule.windowSeconds(),
                        retryAfterSeconds, window.startMs + window.lengthMs);
            }
        }
        return null;
    }

    /**
     * 清理已经结束的窗口，避免内存无限增长。仅删除确认过期且未被轮换的窗口。
     */
    public void sweepExpired(long nowMs) {
        for (Iterator<Map.Entry<String, Window>> it = windows.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<String, Window> e = it.next();
            Window w = e.getValue();
            if (nowMs - w.startMs > w.lengthMs) {
                windows.remove(e.getKey(), w);
            }
        }
    }

    /**
     * 仅用于测试/诊断：查看某来源在某规则上的当前窗口计数（可能在窗口边界瞬间变化）。
     */
    public long currentCount(String source, String ruleId, long nowMs) {
        Window w = windows.get(source + "|" + ruleId);
        if (w == null || nowMs - w.startMs >= w.lengthMs) {
            return 0L;
        }
        return w.current.get();
    }

    /**
     * 一个固定计数窗口。
     */
    private static final class Window {
        private final long startMs;
        private final long lengthMs;
        private final AtomicLong current = new AtomicLong(0);

        private Window(long startMs, long lengthMs) {
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

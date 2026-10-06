package com.github.highcumontoa.trafficshieldjava.security;

import com.github.highcumontoa.trafficshieldjava.model.AllowlistException;
import org.springframework.util.AntPathMatcher;

import java.util.List;

/**
 * 误拦例外匹配器（无状态）：判断一个请求是否命中某条例外。
 * 例外表随规则集原子发布，匹配期间不存在新旧例外混用。
 *
 * <p>匹配维度：来源（Ant 风格，如 {@code ops-*}）与路径（Ant 风格，如 {@code /api/**}）
 * 两个维度同时命中才算命中该条例外；例外表按声明顺序取首个命中。</p>
 */
public final class AllowlistMatcher {

    private static final AntPathMatcher MATCHER = new AntPathMatcher();

    private AllowlistMatcher() {
    }

    /**
     * 判断 （来源， 路径） 是否命中例外表中的任意一条。
     *
     * @return 命中的例外；未命中返回 null
     */
    public static AllowlistException match(List<AllowlistException> exceptions,
                                           String source, String path) {
        if (exceptions == null || exceptions.isEmpty()) {
            return null;
        }
        String src = source == null ? "" : source;
        String p = (path == null || path.isEmpty()) ? "/" : path;
        for (AllowlistException e : exceptions) {
            if (MATCHER.match(e.sourcePattern(), src) && MATCHER.match(e.pathPattern(), p)) {
                return e;
            }
        }
        return null;
    }
}

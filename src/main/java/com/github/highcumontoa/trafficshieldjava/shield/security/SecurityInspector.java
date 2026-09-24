package com.github.highcumontoa.trafficshieldjava.shield.security;

import com.github.highcumontoa.trafficshieldjava.shield.model.RequestContext;
import com.github.highcumontoa.trafficshieldjava.shield.model.SecurityRule;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 安全检测：对请求特征依次应用规则，返回首个命中。
 *
 * <p>检测输入包括：原始 path/query、一次/二次解码后的 path/query（识别双重编码、
 * 编码绕过与空字节），以及请求头与正文。规则按配置顺序评估，
 * {@code urlOnly} 规则只作用于 URL 组件，避免误伤正常正文。</p>
 */
public class SecurityInspector {

    private static final Logger log = LoggerFactory.getLogger(SecurityInspector.class);
    private static final int MAX_EVIDENCE = 80;

    public SecurityInspector() {
    }

    /**
     * 在给定规则快照上执行检测。
     *
     * @return 命中的规则与证据；未命中返回 empty
     */
    public Optional<SecurityHit> inspect(List<SecurityRule> rules, RequestContext request) {
        List<Target> targets = buildTargets(request);
        for (SecurityRule rule : rules) {
            for (Target target : targets) {
                if (rule.urlOnly() && !target.urlComponent) {
                    continue;
                }
                Matcher matcher = rule.pattern().matcher(target.text);
                if (matcher.find()) {
                    String evidence = extract(target, matcher);
                    log.info("[shield] 安全规则命中 rule={}, reason={}, location={}, evidence={}",
                            rule.id(), rule.reason(), target.location, evidence);
                    return Optional.of(new SecurityHit(rule, evidence));
                }
            }
        }
        return Optional.empty();
    }

    private List<Target> buildTargets(RequestContext request) {
        List<Target> targets = new ArrayList<>();
        addUrlTargets(targets, "path", nz(request.path()));
        addUrlTargets(targets, "query", nz(request.rawQuery()));

        if (request.headers() != null) {
            request.headers().forEach((name, values) -> {
                if (values == null) {
                    return;
                }
                for (String value : values) {
                    if (value != null && !value.isBlank()) {
                        targets.add(new Target("header:" + name, value, false));
                    }
                }
            });
        }
        if (request.body() != null && !request.body().isBlank()) {
            targets.add(new Target("body", request.body(), false));
        }
        return targets;
    }

    /**
     * URL 组件依次加入：原始文本、一次解码、二次解码。
     * 解码失败（非法百分号序列）时加入哨兵，由 MALFORMED 规则给出稳定命中。
     */
    private void addUrlTargets(List<Target> targets, String location, String raw) {
        targets.add(new Target(location, raw, true));
        String once = decode(raw);
        if (once == null) {
            targets.add(new Target(location + ":decoded", "%", true));
            return;
        }
        targets.add(new Target(location + ":decoded", once, true));
        String twice = decode(once);
        if (twice == null) {
            targets.add(new Target(location + ":decoded2", "%", true));
        } else if (!twice.equals(once)) {
            targets.add(new Target(location + ":decoded2", twice, true));
        }
    }

    /**
     * @return 解码结果；输入含非法百分号序列时返回 null
     */
    static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private String extract(Target target, Matcher matcher) {
        String matched = matcher.group();
        String evidence = "[" + target.location + "] " + matched;
        if (evidence.length() > MAX_EVIDENCE) {
            evidence = evidence.substring(0, MAX_EVIDENCE) + "...";
        }
        return evidence;
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private record Target(String location, String text, boolean urlComponent) {
    }

    /**
     * 一次命中的检测结果。
     */
    public record SecurityHit(SecurityRule rule, String evidence) {
    }
}

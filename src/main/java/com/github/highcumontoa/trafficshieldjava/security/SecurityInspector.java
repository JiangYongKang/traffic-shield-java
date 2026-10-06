package com.github.highcumontoa.trafficshieldjava.security;

import com.github.highcumontoa.trafficshieldjava.model.AllowlistException;
import com.github.highcumontoa.trafficshieldjava.model.DecisionReason;
import com.github.highcumontoa.trafficshieldjava.model.SecurityRule;
import com.github.highcumontoa.trafficshieldjava.model.ShieldRequest;
import org.springframework.util.AntPathMatcher;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 请求安全检测组件（无状态）。规则编译结果由编排服务持有并随规则集原子发布，
 * 本组件只负责校验/编译与对某一份编译结果执行检测，因此检测期间不存在新旧规则混用。
 *
 * <p>检测流程（对每个文本片段：path / query / 每个 header 值 / body）：</p>
 * <ol>
 *   <li>在原始文本上检查异常编码：孤立百分号、双重编码危险片段、%00 空字节、
 *       %uXXXX、UTF-8 超长编码；</li>
 *   <li>对原始文本与 URL 解码后文本分别按规则声明顺序匹配注入/穿越签名，
 *       首个命中规则即为结论。</li>
 * </ol>
 *
 * <p>误拦例外：例外按 (来源, 路径) 维度匹配，命中后仅豁免其 {@code exemptRuleIds}
 * 列出的签名规则（该条规则视为未命中，继续检查其余规则）。第 1 阶段的内置异常编码
 * 检查（ENC-*）属于明显攻击特征，<b>任何例外都不能豁免</b>，因此配置例外不会放过
 * 双重编码、空字节这类明显攻击请求。</p>
 */
public final class SecurityInspector {

    /** 允许的规则类别（必须映射到稳定的拒绝原因码）。 */
    private static final Set<String> VALID_CATEGORIES = Set.of(
            DecisionReason.SQL_INJECTION.name(),
            DecisionReason.XSS.name(),
            DecisionReason.COMMAND_INJECTION.name(),
            DecisionReason.PATH_TRAVERSAL.name(),
            DecisionReason.SUSPICIOUS_ENCODING.name());

    /** 畸形百分号编码：% 后不是两位合法十六进制（含结尾孤立的 %）。 */
    private static final Pattern MALFORMED_PERCENT =
            Pattern.compile("%(?![0-9a-fA-F]{2})");

    /** 双重编码：危险字符被编码两次后留下的 %25XX 形态。 */
    private static final Pattern DOUBLE_ENCODED_DANGER =
            Pattern.compile("%25(?:2[27ef]|3[bcd]|5[cdf]|2f|00|c0|af)",
                    Pattern.CASE_INSENSITIVE);

    /** 空字节。 */
    private static final Pattern NULL_BYTE =
            Pattern.compile("%00|\\x00", Pattern.CASE_INSENSITIVE);

    /** 非标准 %uXXXX 编码。 */
    private static final Pattern PERCENT_U =
            Pattern.compile("%u[0-9a-fA-F]{4}");

    /** UTF-8 超长编码序列（典型用于绕过 ../ 与过滤器）。 */
    private static final Pattern OVERLONG_UTF8 =
            Pattern.compile("%c(?:0|1)%[0-9a-fA-F]{2}", Pattern.CASE_INSENSITIVE);

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    /** 编译后的规则。 */
    public record CompiledRule(SecurityRule rule, Pattern pattern) {
    }

    /** 编译后的误拦例外（匹配在运行时按 Ant 模式执行）。 */
    public record CompiledException(AllowlistException exception) {
    }

    /**
     * 校验并编译安全规则表。任一条非法即抛 {@link IllegalRuleException}。
     */
    public List<CompiledRule> compile(List<SecurityRule> rules) {
        if (rules == null || rules.isEmpty()) {
            throw new IllegalRuleException("安全规则列表不能为空");
        }
        java.util.LinkedHashMap<String, SecurityRule> seen = new java.util.LinkedHashMap<>();
        for (SecurityRule r : rules) {
            validate(r, seen);
            seen.put(r.id(), r);
        }
        List<CompiledRule> out = new java.util.ArrayList<>(rules.size());
        for (SecurityRule r : rules) {
            try {
                out.add(new CompiledRule(r,
                        Pattern.compile(r.pattern(), Pattern.CASE_INSENSITIVE | Pattern.DOTALL)));
            } catch (Exception e) {
                throw new IllegalRuleException("规则 [" + r.id() + "] 的正则表达式非法: " + e.getMessage());
            }
        }
        return List.copyOf(out);
    }

    private static void validate(SecurityRule r, Map<String, SecurityRule> seen) {
        if (r == null) {
            throw new IllegalRuleException("规则不能为 null");
        }
        if (isBlank(r.id())) {
            throw new IllegalRuleException("规则 id 不能为空");
        }
        if (seen.containsKey(r.id())) {
            throw new IllegalRuleException("规则 id 重复: " + r.id());
        }
        if (isBlank(r.name())) {
            throw new IllegalRuleException("规则 [" + r.id() + "] 的 name 不能为空");
        }
        if (isBlank(r.category()) || !VALID_CATEGORIES.contains(r.category())) {
            throw new IllegalRuleException("规则 [" + r.id() + "] 的 category 非法，允许值: " + VALID_CATEGORIES);
        }
        if (isBlank(r.pattern())) {
            throw new IllegalRuleException("规则 [" + r.id() + "] 的 pattern 不能为空");
        }
    }

    /**
     * 校验并编译误拦例外表（可整体为空）。任一条非法即抛 {@link IllegalRuleException}，
     * 由调用方保证整表校验通过后才发布。
     *
     * @param exceptions    例外表（null/空 表示无例外）
     * @param securityRules 同一次发布的安全规则表，用于校验豁免目标确实存在
     */
    public List<CompiledException> compileExceptions(List<AllowlistException> exceptions,
                                                     List<SecurityRule> securityRules) {
        if (exceptions == null || exceptions.isEmpty()) {
            return List.of();
        }
        Set<String> knownRuleIds = new HashSet<>();
        for (SecurityRule r : securityRules) {
            knownRuleIds.add(r.id());
        }
        Set<String> seen = new HashSet<>();
        List<CompiledException> out = new java.util.ArrayList<>(exceptions.size());
        for (AllowlistException e : exceptions) {
            validateException(e, seen, knownRuleIds);
            seen.add(e.id());
            out.add(new CompiledException(e));
        }
        return List.copyOf(out);
    }

    private static void validateException(AllowlistException e, Set<String> seen,
                                          Set<String> knownRuleIds) {
        if (e == null) {
            throw new IllegalRuleException("例外不能为 null");
        }
        if (isBlank(e.id())) {
            throw new IllegalRuleException("例外 id 不能为空");
        }
        if (seen.contains(e.id())) {
            throw new IllegalRuleException("例外 id 重复: " + e.id());
        }
        if (isBlank(e.sourcePattern()) && isBlank(e.pathPattern())) {
            throw new IllegalRuleException("例外 [" + e.id() + "] 的 sourcePattern 与 pathPattern 不能同时为空");
        }
        if (e.exemptRuleIds() == null || e.exemptRuleIds().isEmpty()) {
            throw new IllegalRuleException("例外 [" + e.id() + "] 的 exemptRuleIds 不能为空");
        }
        for (String ruleId : e.exemptRuleIds()) {
            if (isBlank(ruleId)) {
                throw new IllegalRuleException("例外 [" + e.id() + "] 的 exemptRuleIds 含空白项");
            }
            if (!knownRuleIds.contains(ruleId)) {
                throw new IllegalRuleException("例外 [" + e.id() + "] 豁免的规则不存在: " + ruleId);
            }
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /**
     * 命中结果。
     */
    public record Hit(DecisionReason reason, String ruleId, String detail) {
    }

    /**
     * 基于指定的编译规则快照对请求执行检测（无误拦例外的兼容入口）。
     *
     * @return 首个命中的规则；未命中返回 null
     */
    public Hit inspect(List<CompiledRule> compiled, ShieldRequest request) {
        return inspect(compiled, List.of(), request);
    }

    /**
     * 基于指定的编译规则与例外快照对请求执行检测。
     *
     * @return 首个命中且未被豁免的规则；未命中返回 null
     */
    public Hit inspect(List<CompiledRule> compiled, List<CompiledException> exceptions,
                       ShieldRequest request) {
        Hit h;
        // 1) 原始文本上的异常编码（内置 ENC-* 检查；明显攻击特征，例外不可豁免）
        if ((h = scanEach(request, true, compiled, exceptions)) != null) {
            return h;
        }
        // 2) 原始文本 + 解码后文本上的规则签名匹配（例外在此阶段生效）
        return scanEach(request, false, compiled, exceptions);
    }

    private Hit scanEach(ShieldRequest request, boolean encodingPhase,
                         List<CompiledRule> compiled, List<CompiledException> exceptions) {
        Hit h;
        if ((h = scan(compiled, exceptions, request, "path", request.path(), encodingPhase, true)) != null) {
            return h;
        }
        if ((h = scan(compiled, exceptions, request, "query", request.query(), encodingPhase, true)) != null) {
            return h;
        }
        if (request.headers() != null) {
            for (Map.Entry<String, String> e : request.headers().entrySet()) {
                if ((h = scan(compiled, exceptions, request, "header:" + e.getKey(),
                        e.getValue(), encodingPhase, false)) != null) {
                    return h;
                }
            }
        }
        return scan(compiled, exceptions, request, "body", request.body(), encodingPhase, false);
    }

    private Hit scan(List<CompiledRule> compiled, List<CompiledException> exceptions,
                     ShieldRequest request, String where, String raw,
                     boolean encodingPhase, boolean urlField) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        if (encodingPhase) {
            return detectEncoding(where, raw, urlField);
        }
        Hit h = matchSignatures(compiled, exceptions, request, where, raw, "原始");
        if (h != null) {
            return h;
        }
        String decoded = safeDecode(raw);
        if (!decoded.equals(raw)) {
            return matchSignatures(compiled, exceptions, request, where, decoded, "解码后");
        }
        return null;
    }

    private Hit detectEncoding(String where, String raw, boolean urlField) {
        // 双重编码与空字节在任何字段都是明确的攻击特征，误报率极低
        if (DOUBLE_ENCODED_DANGER.matcher(raw).find()) {
            return new Hit(DecisionReason.SUSPICIOUS_ENCODING, "ENC-DOUBLE-ENCODED",
                    "在[" + where + "]发现双重编码的危险字符");
        }
        if (NULL_BYTE.matcher(raw).find()) {
            return new Hit(DecisionReason.SUSPICIOUS_ENCODING, "ENC-NULL-BYTE",
                    "在[" + where + "]发现空字节编码");
        }
        // 畸形百分号 / %uXXXX / UTF-8 超长编码只在 URL 类字段判定，
        // 避免误伤正文/头里正常的百分比文本（如 "100% 满意"）
        if (urlField) {
            if (MALFORMED_PERCENT.matcher(raw).find()) {
                return new Hit(DecisionReason.SUSPICIOUS_ENCODING, "ENC-MALFORMED-PERCENT",
                        "在[" + where + "]发现畸形百分号编码(%后不是两位十六进制)");
            }
            if (PERCENT_U.matcher(raw).find()) {
                return new Hit(DecisionReason.SUSPICIOUS_ENCODING, "ENC-PERCENT-U",
                        "在[" + where + "]发现非标准 %uXXXX 编码");
            }
            if (OVERLONG_UTF8.matcher(raw).find()) {
                return new Hit(DecisionReason.SUSPICIOUS_ENCODING, "ENC-OVERLONG-UTF8",
                        "在[" + where + "]发现 UTF-8 超长编码序列");
            }
        }
        return null;
    }

    private Hit matchSignatures(List<CompiledRule> compiled, List<CompiledException> exceptions,
                                ShieldRequest request, String where, String text, String view) {
        for (CompiledRule c : compiled) {
            Matcher m = c.pattern().matcher(text);
            if (!m.find()) {
                continue;
            }
            if (isExempted(exceptions, c.rule().id(), request)) {
                continue; // 该规则被例外豁免，视为未命中，继续检查其余规则
            }
            String snippet = m.group();
            if (snippet.length() > 32) {
                snippet = snippet.substring(0, 32) + "...";
            }
            return new Hit(DecisionReason.valueOf(c.rule().category()), c.rule().id(),
                    "在[" + where + "]" + view + "内容命中规则 " + c.rule().id()
                            + "(" + c.rule().name() + ")，匹配片段=[" + snippet + "]");
        }
        return null;
    }

    /**
     * 判断指定安全规则对本请求是否被某条例外豁免。
     * 例外为 null 的匹配维度视为不限制；内置 ENC-* 检查不走此逻辑，不可豁免。
     */
    private boolean isExempted(List<CompiledException> exceptions, String ruleId,
                               ShieldRequest request) {
        if (exceptions.isEmpty()) {
            return false;
        }
        for (CompiledException ce : exceptions) {
            AllowlistException e = ce.exception();
            if (!e.exemptRuleIds().contains(ruleId)) {
                continue;
            }
            if (e.sourcePattern() != null
                    && !pathMatcher.match(e.sourcePattern(), request.source())) {
                continue;
            }
            if (e.pathPattern() != null && !pathMatcher.match(e.pathPattern(),
                    request.path() == null ? "/" : request.path())) {
                continue;
            }
            return true;
        }
        return false;
    }

    private static String safeDecode(String s) {
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // 畸形编码已在编码阶段拦截；解码失败时原样返回
            return s;
        }
    }
}

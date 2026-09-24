package com.github.highcumontoa.trafficshieldjava.web;

import com.github.highcumontoa.trafficshieldjava.config.ShieldProperties;
import com.github.highcumontoa.trafficshieldjava.model.CheckRequest;
import com.github.highcumontoa.trafficshieldjava.model.DecisionReason;
import com.github.highcumontoa.trafficshieldjava.model.RuleSet;
import com.github.highcumontoa.trafficshieldjava.model.RuleUpdateRequest;
import com.github.highcumontoa.trafficshieldjava.model.ShieldDecision;
import com.github.highcumontoa.trafficshieldjava.model.ShieldRequest;
import com.github.highcumontoa.trafficshieldjava.model.ShieldStats;
import com.github.highcumontoa.trafficshieldjava.service.TrafficShieldService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 防护相关 HTTP 入口。
 *
 * <ul>
 *   <li>{@code ANY /gateway/**}：模拟网关入口，对转发流量做安全检测与限流，
 *       放行时返回 200（虚拟"已转发"），安全拒绝 403，限流 429；</li>
 *   <li>{@code POST /shield/check}：本地可验证的 JSON 检查入口，直接提交请求特征，
 *       判定逻辑与网关入口完全相同（同一服务方法），返回 200 并在体内给出结论；</li>
 *   <li>{@code GET /shield/rules} / {@code PUT /shield/rules}：规则查询与原子更新；</li>
 *   <li>{@code GET /shield/stats}：命中/拒绝/限流统计快照。</li>
 * </ul>
 */
@RestController
@RequestMapping
public class ShieldController {

    private final TrafficShieldService service;
    private final ShieldProperties properties;

    public ShieldController(TrafficShieldService service, ShieldProperties properties) {
        this.service = service;
        this.properties = properties;
    }

    /**
     * 网关入口：消费路径、查询串、关键请求头与请求体。
     */
    @RequestMapping("/gateway/**")
    public ResponseEntity<Map<String, Object>> gateway(HttpServletRequest httpRequest,
                                                       @RequestBody(required = false) String body) {
        ShieldRequest request = new ShieldRequest(
                httpRequest.getMethod(),
                httpRequest.getRequestURI(),
                httpRequest.getQueryString(),
                extractHeaders(httpRequest),
                body,
                resolveSource(httpRequest));
        return toHttpResponse(service.check(request));
    }

    /**
     * JSON 检查入口：显式给出请求特征，便于本地直接验证判定。
     */
    @PostMapping("/shield/check")
    public ResponseEntity<Map<String, Object>> check(@RequestBody CheckRequest req) {
        ShieldRequest request = new ShieldRequest(
                req.method() == null ? "GET" : req.method(),
                req.path() == null ? "/" : req.path(),
                req.query(),
                req.headers() == null ? Map.of() : req.headers(),
                req.body(),
                req.source() == null || req.source().isBlank() ? "json-client" : req.source());
        // 检查入口始终返回 200，由响应体表达结论，方便调用方断言原因码
        return ResponseEntity.ok(toBody(service.check(request)));
    }

    /**
     * 查询当前生效规则。
     */
    @GetMapping("/shield/rules")
    public RuleSet rules() {
        return service.currentRules();
    }

    /**
     * 原子更新规则：字段为 null 的部分保持不变，任一条非法则整体拒绝。
     */
    @PutMapping("/shield/rules")
    public Map<String, Object> updateRules(@RequestBody RuleUpdateRequest request) {
        long version = service.updateRules(request);
        return Map.of("updated", true, "rulesVersion", version);
    }

    /**
     * 查询统计快照。
     */
    @GetMapping("/shield/stats")
    public ShieldStats stats() {
        return service.stats();
    }

    /**
     * 将判定结论映射为网关入口的 HTTP 响应：放行 200、安全拒绝 403、限流 429。
     */
    private ResponseEntity<Map<String, Object>> toHttpResponse(ShieldDecision d) {
        HttpHeaders headers = new HttpHeaders();
        if (d.reason() == DecisionReason.RATE_LIMITED) {
            headers.add(HttpHeaders.RETRY_AFTER, String.valueOf(d.retryAfterSeconds()));
            return ResponseEntity.status(429).headers(headers).body(toBody(d));
        }
        if (!d.allowed()) {
            return ResponseEntity.status(403).body(toBody(d));
        }
        return ResponseEntity.ok(toBody(d));
    }

    private Map<String, Object> toBody(ShieldDecision d) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("allowed", d.allowed());
        body.put("status", d.allowed() ? "ALLOW" : "REJECT");
        body.put("reason", d.reason().name());
        body.put("ruleId", d.ruleId());
        body.put("message", d.message());
        body.put("retryAfterSeconds", d.retryAfterSeconds());
        body.put("rulesVersion", d.rulesVersion());
        body.put("source", d.source());
        body.put("path", d.path());
        return body;
    }

    private String resolveSource(HttpServletRequest req) {
        String header = properties.getSourceHeader();
        String value = req.getHeader(header);
        if (value != null && !value.isBlank()) {
            // X-Forwarded-For 可能是逗号分隔链，取第一个（最原始来源）
            int comma = value.indexOf(',');
            return (comma > 0 ? value.substring(0, comma) : value).trim();
        }
        return req.getRemoteAddr() == null ? "unknown" : req.getRemoteAddr();
    }

    private Map<String, String> extractHeaders(HttpServletRequest req) {
        // 只把"业务方可写的输入头"纳入检测，避免 accept: */*、User-Agent、Cookie
        // 等基础设施头里出现的正常片段（如 */、--）被安全规则误判。
        Map<String, String> headers = new LinkedHashMap<>();
        req.getHeaderNames().asIterator().forEachRemaining(name -> {
            String lower = name.toLowerCase();
            boolean inspectable = lower.equals("referer")
                    || lower.startsWith("x-") && !lower.equals("x-forwarded-for")
                    && !lower.equals("x-real-ip");
            if (inspectable) {
                headers.put(name, req.getHeader(name));
            }
        });
        return headers;
    }
}

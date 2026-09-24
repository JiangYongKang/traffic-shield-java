package com.github.highcumontoa.trafficshieldjava.shield.web;

import com.github.highcumontoa.trafficshieldjava.shield.config.ShieldProperties;
import com.github.highcumontoa.trafficshieldjava.shield.model.Decision;
import com.github.highcumontoa.trafficshieldjava.shield.model.RequestContext;
import com.github.highcumontoa.trafficshieldjava.shield.model.ShieldResult;
import com.github.highcumontoa.trafficshieldjava.shield.service.ShieldService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 对受防护入口（/api/**）执行统一的检查与处置。
 */
@Component
@Order(1)
public class ShieldFilter extends OncePerRequestFilter {

    private static final List<String> FORWARDED_HEADERS =
            List.of("X-Forwarded-For", "X-Real-IP");

    private final ShieldService shieldService;
    private final ShieldProperties properties;
    private final ObjectMapper objectMapper;

    public ShieldFilter(ShieldService shieldService,
                        ShieldProperties properties,
                        ObjectMapper objectMapper) {
        this.shieldService = shieldService;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!properties.isEnabled()) {
            return true;
        }
        // 管理与统计接口自身不受防护，避免限流后无法查询状态
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(
                request, readBody(request));

        RequestContext context = buildContext(cached);
        ShieldResult result = shieldService.check(context);

        if (result.decision() == Decision.ALLOW) {
            filterChain.doFilter(cached, response);
            return;
        }
        writeRejection(response, result);
    }

    private RequestContext buildContext(HttpServletRequest request) {
        String path = request.getRequestURI();
        String query = request.getQueryString();

        Map<String, List<String>> headers = new LinkedHashMap<>();
        List<String> headerNames = Collections.list(request.getHeaderNames());
        for (String name : headerNames) {
            // Host / Content-Length 等协议头无检测价值，仅检查与用户输入相关的头
            if (FORWARDED_HEADERS.contains(name) || "User-Agent".equalsIgnoreCase(name)
                    || "Referer".equalsIgnoreCase(name) || "Cookie".equalsIgnoreCase(name)) {
                headers.put(name, Collections.list(request.getHeaders(name)));
            }
        }
        return new RequestContext(resolveSource(request), request.getMethod(),
                path, query, headers, readCachedBody(request));
    }

    private String resolveSource(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            // 取最左侧（最初来源）
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
    }

    private String readCachedBody(HttpServletRequest request) {
        if (request instanceof CachedBodyHttpServletRequest cached) {
            return cached.getCachedBody();
        }
        return "";
    }

    private byte[] readBody(HttpServletRequest request) throws IOException {
        if (request instanceof CachedBodyHttpServletRequest cached) {
            return cached.getCachedBody().getBytes(StandardCharsets.UTF_8);
        }
        return request.getInputStream().readAllBytes();
    }

    private void writeRejection(HttpServletResponse response, ShieldResult result) throws IOException {
        boolean rateLimited = result.decision() == Decision.REJECT_RATE_LIMIT;
        response.setStatus(rateLimited ? 429 : HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        if (rateLimited) {
            long retrySeconds = Math.max(1L, (result.retryAfterMillis() + 999L) / 1000L);
            response.setHeader("Retry-After", String.valueOf(retrySeconds));
            response.setHeader("X-Retry-After-Ms", String.valueOf(result.retryAfterMillis()));
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", rateLimited ? 429 : 403);
        body.put("error", rateLimited ? "rate_limited" : "request_rejected");
        body.put("reason", result.reason() == null ? null : result.reason().name());
        body.put("ruleId", result.ruleId());
        body.put("evidence", result.evidence());
        body.put("retryable", rateLimited);
        if (rateLimited) {
            body.put("retryAfterMs", result.retryAfterMillis());
        }

        try (OutputStream out = response.getOutputStream()) {
            out.write(objectMapper.writeValueAsBytes(body));
        }
    }
}

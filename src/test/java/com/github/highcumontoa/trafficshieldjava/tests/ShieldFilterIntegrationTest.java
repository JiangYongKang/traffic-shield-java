package com.github.highcumontoa.trafficshieldjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端集成测试：过滤器 + 防护门面 + 控制器，验证不同入口下结论一致可解释。
 */
@SpringBootTest
@AutoConfigureMockMvc
class ShieldFilterIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(ShieldFilterIntegrationTest.class);

    @Autowired
    private MockMvc mockMvc;

    @Test
    void normalTrafficPasses() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/hello").param("name", "Vincent"))
                .andExpect(status().isOk())
                .andReturn();
        log.info("[test] 正常流量响应: {}", result.getResponse().getContentAsString());
        assertTrue(result.getResponse().getContentAsString().contains("Vincent"));
    }

    @Test
    void suspiciousTrafficReturns403WithDistinctReason() throws Exception {
        // 直接给原始查询串（与真实网关收到的 queryString 一致，不经表单编码）
        MvcResult sqliRaw = mockMvc.perform(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                .get("/api/hello?name=admin'%20or%20'1'='1"))
                .andExpect(status().isForbidden())
                .andReturn();
        log.info("[test] SQL 注入响应: {}", sqliRaw.getResponse().getContentAsString());
        assertTrue(sqliRaw.getResponse().getContentAsString().contains("SQL_INJECTION"));
        assertTrue(sqliRaw.getResponse().getContentAsString().contains("SEC-SQLI"));

        MvcResult traversal = mockMvc.perform(
                        get("/api/hello?next=/a/%2e%2e/%2e%2e/etc/passwd"))
                .andExpect(status().isForbidden())
                .andReturn();
        log.info("[test] 编码穿越响应: {}", traversal.getResponse().getContentAsString());
        assertTrue(traversal.getResponse().getContentAsString().contains("PATH_TRAVERSAL"));

        MvcResult xss = mockMvc.perform(post("/api/submit")
                        .contentType("application/json")
                        .content("{\"comment\":\"<script>x</script>\"}"))
                .andExpect(status().isForbidden())
                .andReturn();
        log.info("[test] XSS 响应: {}", xss.getResponse().getContentAsString());
        assertTrue(xss.getResponse().getContentAsString().contains("XSS_ATTEMPT"));

        MvcResult malformed = mockMvc.perform(get("/api/hello?name=%zz"))
                .andExpect(status().isForbidden())
                .andReturn();
        log.info("[test] 异常编码响应: {}", malformed.getResponse().getContentAsString());
        assertTrue(malformed.getResponse().getContentAsString().contains("MALFORMED_ENCODING"));
    }

    @Test
    void overLimitReturns429WithRetryHint() throws Exception {
        // /api/submit 默认窗口配额 5；使用不同来源前缀避免与其它测试相互干扰
        MvcResult blocked = null;
        for (int i = 1; i <= 6; i++) {
            MvcResult r = mockMvc.perform(post("/api/submit")
                            .header("X-Forwarded-For", "203.0.113.77")
                            .contentType("application/json")
                            .content("\"ok\""))
                    .andReturn();
            log.info("[test] submit 第 {} 次 status={}", i, r.getResponse().getStatus());
            if (i <= 5) {
                assertEquals(200, r.getResponse().getStatus(), "前 5 次必须放行");
            } else {
                blocked = r;
            }
        }
        assertNotNull(blocked);
        assertEquals(429, blocked.getResponse().getStatus());
        assertEquals("RATE_LIMITED", blocked.getResponse().getContentAsString()
                .replaceAll(".*\"reason\":\"([^\"]+)\".*", "$1"));
        assertNotNull(blocked.getResponse().getHeader("Retry-After"));
        assertTrue(Long.parseLong(blocked.getResponse().getHeader("X-Retry-After-Ms")) > 0);
        assertTrue(blocked.getResponse().getContentAsString().contains("\"retryable\":true"));
        log.info("[test] 限流响应: {}, Retry-After={}",
                blocked.getResponse().getContentAsString(),
                blocked.getResponse().getHeader("Retry-After"));
    }

    @Test
    void adminEndpointsAreNotShielded() throws Exception {
        // 即使 /api 已被打满，统计接口仍可访问
        MvcResult stats = mockMvc.perform(get("/shield/stats"))
                .andExpect(status().isOk())
                .andReturn();
        log.info("[test] 统计接口响应: {}", stats.getResponse().getContentAsString());
        assertTrue(stats.getResponse().getContentAsString().contains("total"));
        assertNull(stats.getResponse().getHeader("Retry-After"));
    }
}

package com.github.highcumontoa.trafficshieldjava.tests;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 不同入口的一致性测试与端到端 HTTP 语义测试。
 */
@SpringBootTest
@AutoConfigureMockMvc
class EndpointConsistencyTest {

    private static final Logger log = LoggerFactory.getLogger(EndpointConsistencyTest.class);

    @Autowired
    private MockMvc mvc;

    private String checkJson(String path, String query, String source) {
        String q = query == null ? "" : ", \"query\": \"" + query + "\"";
        return "{ \"method\":\"GET\", \"path\":\"" + path + "\"" + q
                + ", \"source\":\"" + source + "\"}";
    }

    @Test
    void gatewayAndCheckEndpointsAgreeOnSuspiciousTraffic() throws Exception {
        String path = "/gateway/products";
        // 逻辑等价的可疑特征：网关入口用真实空格（MockMvc 会编码为 %20，服务端解码还原），
        // JSON 入口直接给 %20（解码后为空格），两者解码后的查询串一致
        String gatewayQuery = "id=1 OR 1=1";
        String checkQuery = "id=1%20OR%201=1";

        // 直接带原始 query string 请求网关入口
        MvcResult gateway = mvc.perform(get(path + "?" + gatewayQuery)
                        .header("X-Forwarded-For", "src-consistency"))
                .andExpect(status().isForbidden()).andReturn();

        MvcResult check = mvc.perform(post("/shield/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(checkJson("/gateway/products", checkQuery, "src-consistency")))
                .andExpect(status().isOk()).andReturn();

        String checkBody = check.getResponse().getContentAsString();
        String gatewayBody = gateway.getResponse().getContentAsString();
        log.info("[入口一致性] 可疑流量 gateway={}", gatewayBody);
        log.info("[入口一致性] 可疑流量 check  ={}", checkBody);

        // 两个入口的原因码必须一致且可区分
        assertEquals(true, gatewayBody.contains("\"reason\":\"SQL_INJECTION\""));
        assertEquals(true, checkBody.contains("\"reason\":\"SQL_INJECTION\""));
        assertEquals(true, checkBody.contains("\"allowed\":false"));
    }

    @Test
    void normalTrafficPassesGateway() throws Exception {
        MvcResult r = mvc.perform(get("/gateway/api/orders")
                        .header("X-Forwarded-For", "src-normal")
                        .param("page", "2"))
                .andExpect(status().isOk()).andReturn();
        log.info("[入口一致性] 正常流量 gateway => {}", r.getResponse().getContentAsString());
        assertEquals(true, r.getResponse().getContentAsString().contains("\"allowed\":true"));
    }

    @Test
    void rateLimitedTrafficReturns429AndRetryAfter() throws Exception {
        // 默认配置每窗口 10 次；用独立来源连发 12 次
        String source = "src-429";
        MvcResult limited = null;
        for (int i = 1; i <= 12; i++) {
            MvcResult r = mvc.perform(get("/gateway/api/x")
                            .header("X-Forwarded-For", source))
                    .andReturn();
            if (r.getResponse().getStatus() == 429) {
                limited = r;
                break;
            }
        }
        assertNotNull(limited, "第 11 个请求必须被限流并返回 429");
        String retryAfter = limited.getResponse().getHeader("Retry-After");
        assertNotNull(retryAfter, "429 必须携带 Retry-After 可重试提示");
        log.info("[入口一致性] 超限流量 gateway => 429, Retry-After={}s, body={}",
                retryAfter, limited.getResponse().getContentAsString());
        assertEquals(true, limited.getResponse().getContentAsString().contains("\"reason\":\"RATE_LIMITED\""));

        // check 入口对同样的来源继续判定，也应是限流结论（状态码 200，体内表达）
        MvcResult check = mvc.perform(post("/shield/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(checkJson("/gateway/api/x", null, source)))
                .andExpect(status().isOk()).andReturn();
        log.info("[入口一致性] 超限流量 check   => {}", check.getResponse().getContentAsString());
        assertEquals(true, check.getResponse().getContentAsString().contains("\"reason\":\"RATE_LIMITED\""));
    }

    @Test
    void illegalRuleUpdateViaHttpReturns400AndKeepsRules() throws Exception {
        String before = mvc.perform(get("/shield/rules"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        MvcResult bad = mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .put("/shield/rules")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"securityRules\":[{\"id\":\"X\",\"name\":\"x\","
                                + "\"category\":\"BAD\",\"pattern\":\"a\"}]}"))
                .andExpect(status().isBadRequest()).andReturn();
        log.info("[入口一致性] 非法规则更新 => {}", bad.getResponse().getContentAsString());

        String after = mvc.perform(get("/shield/rules"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertEquals(before, after, "非法更新后规则表必须保持不变");
    }
}

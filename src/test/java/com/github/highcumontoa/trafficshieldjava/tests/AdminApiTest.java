package com.github.highcumontoa.trafficshieldjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * 规则更新与统计查询的 HTTP 契约测试。
 */
@SpringBootTest
@AutoConfigureMockMvc
class AdminApiTest {

    private static final Logger log = LoggerFactory.getLogger(AdminApiTest.class);

    @Autowired
    private MockMvc mockMvc;

    @Test
    void invalidRulesReturn400AndKeepOldRules() throws Exception {
        // 先取一次当前规则（规则数基线）
        MvcResult rulesBefore = mockMvc.perform(get("/shield/rules"))
                .andExpect(status().isOk()).andReturn();
        String beforeBody = rulesBefore.getResponse().getContentAsString();
        log.info("[test] 更新前规则长度={}", beforeBody.length());

        String invalid = """
                {
                  "securityRules": [],
                  "rateLimitRules": [
                    {"id":"BAD","pathPattern":"/api/hello","limit":-3,"windowMillis":1000}
                  ]
                }
                """;
        MvcResult resp = mockMvc.perform(put("/shield/rules")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalid))
                .andExpect(status().isBadRequest())
                .andReturn();
        log.info("[test] 非法更新响应: {}", resp.getResponse().getContentAsString());
        assertTrue(resp.getResponse().getContentAsString().contains("invalid_rules"));

        MvcResult rulesAfter = mockMvc.perform(get("/shield/rules"))
                .andExpect(status().isOk()).andReturn();
        assertEquals(beforeBody, rulesAfter.getResponse().getContentAsString(),
                "非法更新后规则必须与更新前完全一致");
        log.info("[test] 非法更新被拒绝，规则保持不变");
    }

    @Test
    void statsEndpointExposesConsistentSnapshot() throws Exception {
        MvcResult stats = mockMvc.perform(get("/shield/stats"))
                .andExpect(status().isOk()).andReturn();
        String body = stats.getResponse().getContentAsString();
        log.info("[test] 统计快照: {}", body);
        assertTrue(body.contains("\"total\"") && body.contains("\"rejectedByReason\""));
    }
}

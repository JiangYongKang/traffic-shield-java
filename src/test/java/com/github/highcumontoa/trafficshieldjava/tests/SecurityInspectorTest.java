package com.github.highcumontoa.trafficshieldjava.tests;

import com.github.highcumontoa.trafficshieldjava.model.DecisionReason;
import com.github.highcumontoa.trafficshieldjava.model.SecurityRule;
import com.github.highcumontoa.trafficshieldjava.model.ShieldRequest;
import com.github.highcumontoa.trafficshieldjava.security.DefaultRules;
import com.github.highcumontoa.trafficshieldjava.security.SecurityInspector;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 安全检测单测：正常请求放行，各类可疑请求返回可区分的稳定原因码。
 */
class SecurityInspectorTest {

    private static final Logger log = LoggerFactory.getLogger(SecurityInspectorTest.class);

    private final SecurityInspector inspector = new SecurityInspector();
    private final List<SecurityInspector.CompiledRule> compiled =
            inspector.compile(DefaultRules.securityRules());

    private SecurityInspector.Hit check(String path, String query, String body) {
        ShieldRequest req = new ShieldRequest("GET", path, query, Map.of(), body, "tester");
        SecurityInspector.Hit hit = inspector.inspect(compiled, req);
        log.info("[安全检测] 特征 path={} query={} body={} => {} | 依据: {}",
                path, query, body,
                hit == null ? "放行" : hit.reason() + "/" + hit.ruleId(),
                hit == null ? "未命中规则" : hit.detail());
        return hit;
    }

    @Test
    void normalRequestsAreNotBlocked() {
        assertNull(check("/api/orders", "page=2&size=20", null));
        assertNull(check("/products/100/reviews", "sort=asc", "很好，质量不错 100% 满意"));
        // 合法的百分号编码、普通数学表达式与标签类文本都不应误伤
        assertNull(check("/search", "q=hello%20world", null));
        assertNull(check("/calc", "expr=2-1", null));
        assertNull(check("/notes", null, "please update the doc by 10:00"));
    }

    @Test
    void sqlInjectionIsDetectedWithDistinctReason() {
        SecurityInspector.Hit h = check("/products", "id=1%20OR%201=1", null);
        // OR 1=1 属于堆叠/布尔注入
        assertNotNull(h);
        assertEquals(DecisionReason.SQL_INJECTION, h.reason());
        assertEquals("SQL-003", h.ruleId());

        SecurityInspector.Hit h2 = check("/products", "id=1;drop%20table%20users", null);
        assertEquals(DecisionReason.SQL_INJECTION, h2.reason());

        SecurityInspector.Hit h3 = check("/login", null, "' or '1'='1");
        assertEquals(DecisionReason.SQL_INJECTION, h3.reason());

        SecurityInspector.Hit h4 = check("/p", "x=1%20union%20select%20*%20from%20users", null);
        assertEquals(DecisionReason.SQL_INJECTION, h4.reason());
    }

    @Test
    void xssIsDetectedWithDistinctReason() {
        SecurityInspector.Hit h = check("/comments", null, "<script>alert('x')</script>");
        assertNotNull(h);
        assertEquals(DecisionReason.XSS, h.reason());
        assertEquals("XSS-001", h.ruleId());

        SecurityInspector.Hit h2 = check("/comments", null, "<img src=x onerror=alert(1)>");
        assertEquals(DecisionReason.XSS, h2.reason());
    }

    @Test
    void commandInjectionIsDetectedWithDistinctReason() {
        SecurityInspector.Hit h = check("/tools/ping", "host=8.8.8.8;cat%20/etc/passwd", null);
        assertNotNull(h);
        // /etc/passwd 会先命中命令连接片段；只要属于命令注入或路径穿越中的一种稳定类别即可
        assertEquals(DecisionReason.COMMAND_INJECTION, h.reason());

        SecurityInspector.Hit h2 = check("/run", "cmd=`whoami`", null);
        assertEquals(DecisionReason.COMMAND_INJECTION, h2.reason());
    }

    @Test
    void pathTraversalIsDetectedWithDistinctReason() {
        SecurityInspector.Hit h = check("/files/../../etc/passwd", null, null);
        assertNotNull(h);
        assertEquals(DecisionReason.PATH_TRAVERSAL, h.reason());

        // 编码后的穿越，解码后同样要被识别
        SecurityInspector.Hit h2 = check("/files", "name=..%2F..%2Fetc%2Fpasswd", null);
        assertEquals(DecisionReason.PATH_TRAVERSAL, h2.reason());
    }

    @Test
    void suspiciousEncodingIsDetectedWithDistinctReason() {
        // 孤立百分号
        SecurityInspector.Hit h = check("/search", "q=50%off%today", null);
        assertNotNull(h);
        assertEquals(DecisionReason.SUSPICIOUS_ENCODING, h.reason());
        assertEquals("ENC-MALFORMED-PERCENT", h.ruleId());

        // 双重编码的 ../ （%252e%252e%252f）
        SecurityInspector.Hit h2 = check("/files", "name=%252e%252e%252fetc", null);
        assertEquals(DecisionReason.SUSPICIOUS_ENCODING, h2.reason());

        // 空字节
        SecurityInspector.Hit h3 = check("/files", "name=a.jsp%00.jpg", null);
        assertEquals(DecisionReason.SUSPICIOUS_ENCODING, h3.reason());

        // UTF-8 超长编码
        SecurityInspector.Hit h4 = check("/files", "name=%C0%AFetc%2Fpasswd", null);
        assertEquals(DecisionReason.SUSPICIOUS_ENCODING, h4.reason());
    }
}

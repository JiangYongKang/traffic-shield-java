package com.github.highcumontoa.trafficshieldjava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.highcumontoa.trafficshieldjava.shield.config.DefaultRules;
import com.github.highcumontoa.trafficshieldjava.shield.config.ShieldConfig;
import com.github.highcumontoa.trafficshieldjava.shield.model.RejectReason;
import com.github.highcumontoa.trafficshieldjava.shield.model.RequestContext;
import com.github.highcumontoa.trafficshieldjava.shield.security.SecurityInspector;
import com.github.highcumontoa.trafficshieldjava.shield.security.SecurityInspector.SecurityHit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 安全检测单测：正常请求不误伤，可疑请求原因稳定可区分。
 */
class SecurityInspectorTest {

    private static final Logger log = LoggerFactory.getLogger(SecurityInspectorTest.class);

    private final ShieldConfig config = DefaultRules.defaultConfig();
    private final SecurityInspector inspector = new SecurityInspector();

    private Optional<SecurityHit> check(String method, String path, String query, String body) {
        RequestContext ctx = new RequestContext("10.0.0.1", method, path, query,
                Map.of("User-Agent", List.of("junit")), body);
        Optional<SecurityHit> hit = inspector.inspect(config.securityRules(), ctx);
        log.info("[test] 请求特征 method={}, path={}, query={}, body={} => {}",
                method, path, query, body,
                hit.map(h -> "命中 " + h.rule().id() + "/" + h.rule().reason()
                        + " 依据=" + h.evidence()).orElse("放行"));
        return hit;
    }

    @Test
    void normalRequestsMustPass() {
        List<String[]> cases = List.of(
                new String[]{"GET", "/api/hello", "name=Vincent", null},
                new String[]{"GET", "/products", "q=spring boot 21&page=2", null},
                new String[]{"POST", "/api/submit", null,
                        "{\"content\":\"进度 100% 完成，价格打 9 折\",\"note\":\"a-b_c.d\"}"},
                new String[]{"GET", "/files", "name=report 2026.pdf", null},
                new String[]{"GET", "/search", "q=it's a nice day", null}
        );
        for (String[] c : cases) {
            assertTrue(check(c[0], c[1], c[2], c[3]).isEmpty(),
                    "正常请求被误拦截: " + String.join("?", c[1], String.valueOf(c[2])));
        }
    }

    @Test
    void malformedEncodingMustBeRejected() {
        Optional<SecurityHit> hit = check("GET", "/api/hello", "name=%zz", null);
        assertTrue(hit.isPresent());
        assertEquals(RejectReason.MALFORMED_ENCODING, hit.get().rule().reason());
        assertEquals("SEC-ENCODING-001", hit.get().rule().id());

        Optional<SecurityHit> nul = check("GET", "/api/hello", "name=a%00b", null);
        assertTrue(nul.isPresent());
        assertEquals(RejectReason.MALFORMED_ENCODING, nul.get().rule().reason());
    }

    @Test
    void traversalAndDoubleEncodingMustBeRejected() {
        Optional<SecurityHit> raw = check("GET", "/files/../etc/passwd", null, null);
        assertTrue(raw.isPresent());
        assertEquals(RejectReason.PATH_TRAVERSAL, raw.get().rule().reason());

        // 双重编码的 ../  (%2e%2e%2f 先被 URLDecoder 还原为 ../)
        Optional<SecurityHit> encoded = check("GET", "/files/%2e%2e%2fetc/passwd", null, null);
        assertTrue(encoded.isPresent());
        assertEquals(RejectReason.PATH_TRAVERSAL, encoded.get().rule().reason());
    }

    @Test
    void sqlInjectionMustBeRejected() {
        Optional<SecurityHit> tautology = check("GET", "/login",
                "username=admin' or '1'='1&password=x", null);
        assertTrue(tautology.isPresent());
        assertEquals(RejectReason.SQL_INJECTION, tautology.get().rule().reason());

        Optional<SecurityHit> union = check("POST", "/api/submit", null,
                "{\"q\":\"1 UNION SELECT password FROM users\"}");
        assertTrue(union.isPresent());
        assertEquals(RejectReason.SQL_INJECTION, union.get().rule().reason());
    }

    @Test
    void xssMustBeRejected() {
        Optional<SecurityHit> script = check("POST", "/api/submit", null,
                "{\"comment\":\"<script>alert(1)</script>\"}");
        assertTrue(script.isPresent());
        assertEquals(RejectReason.XSS_ATTEMPT, script.get().rule().reason());

        Optional<SecurityHit> handler = check("GET", "/comments",
                "text=<img src=x onerror=alert(1)>", null);
        assertTrue(handler.isPresent());
        assertEquals(RejectReason.XSS_ATTEMPT, handler.get().rule().reason());
    }

    @Test
    void rejectReasonsMustBeDistinguishable() {
        RejectReason encoding = check("GET", "/p", "q=%zz", null).get().rule().reason();
        RejectReason traversal = check("GET", "/p/../x", null, null).get().rule().reason();
        RejectReason sqli = check("GET", "/p", "q=' or '1'='1", null).get().rule().reason();
        RejectReason xss = check("GET", "/p", "q=<script>", null).get().rule().reason();
        log.info("[test] 四类拒绝原因: {}, {}, {}, {}", encoding, traversal, sqli, xss);
        assertFalse(encoding.equals(traversal) || encoding.equals(sqli) || encoding.equals(xss)
                || traversal.equals(sqli) || traversal.equals(xss) || sqli.equals(xss),
                "拒绝原因必须两两可区分");
    }
}

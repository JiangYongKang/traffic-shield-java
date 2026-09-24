package com.github.highcumontoa.trafficshieldjava.web;

import com.github.highcumontoa.trafficshieldjava.security.IllegalRuleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 全局异常处理：非法规则更新等用户错误返回 400 与稳定原因码，
 * 规则本身不会因为一次失败的更新而改变。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(IllegalRuleException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalRule(IllegalRuleException e) {
        log.warn("规则更新被拒绝，原有规则保持不变: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body("ILLEGAL_RULE", e.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleUnreadable(HttpMessageNotReadableException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(body("MALFORMED_REQUEST", "请求体不是合法 JSON 或字段类型错误"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOther(Exception e) {
        log.error("防护入口处理异常", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(body("INTERNAL_ERROR", e.getMessage()));
    }

    private Map<String, Object> body(String reason, String message) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("updated", false);
        map.put("reason", reason);
        map.put("message", message);
        return map;
    }
}

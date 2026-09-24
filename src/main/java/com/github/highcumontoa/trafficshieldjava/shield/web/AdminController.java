package com.github.highcumontoa.trafficshieldjava.shield.web;

import com.github.highcumontoa.trafficshieldjava.shield.config.InvalidRuleException;
import com.github.highcumontoa.trafficshieldjava.shield.config.ShieldConfig;
import com.github.highcumontoa.trafficshieldjava.shield.service.ShieldService;
import com.github.highcumontoa.trafficshieldjava.shield.stats.StatsSnapshot;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 规则更新与状态查询入口。
 */
@RestController
@RequestMapping("/shield")
public class AdminController {

    private static final Logger log = LoggerFactory.getLogger(AdminController.class);

    private final ShieldService shieldService;

    public AdminController(ShieldService shieldService) {
        this.shieldService = shieldService;
    }

    /** 一致的统计快照 */
    @GetMapping("/stats")
    public StatsSnapshot stats() {
        return shieldService.statsSnapshot();
    }

    /** 当前生效规则 */
    @GetMapping("/rules")
    public ShieldConfig rules() {
        return shieldService.currentConfig();
    }

    /**
     * 原子更新规则；非法规则返回 400，且原有规则保持不变。
     */
    @PutMapping("/rules")
    public Map<String, Object> updateRules(@RequestBody ShieldConfig config) {
        shieldService.updateConfig(config);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("updated", true);
        result.put("securityRules", config.securityRules().size());
        result.put("rateLimitRules", config.rateLimitRules().size());
        return result;
    }

    @ExceptionHandler(InvalidRuleException.class)
    public ResponseEntity<Map<String, Object>> handleInvalid(InvalidRuleException e) {
        log.warn("[shield] 规则更新被拒绝(非法规则，保留原规则): {}", e.getMessage());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("updated", false);
        body.put("error", "invalid_rules");
        body.put("message", e.getMessage());
        return ResponseEntity.badRequest().body(body);
    }
}

package com.github.highcumontoa.trafficshieldjava.shield.web;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 受防护的演示入口：不同入口共享同一套防护判定。
 */
@RestController
@RequestMapping("/api")
public class DemoController {

    @GetMapping("/hello")
    public Map<String, Object> hello(@RequestParam(name = "name", required = false) String name) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("entry", "hello");
        result.put("message", "hello, " + (name == null ? "guest" : name));
        return result;
    }

    @PostMapping("/submit")
    public Map<String, Object> submit(@RequestBody(required = false) String body) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("entry", "submit");
        result.put("received", body);
        return result;
    }
}

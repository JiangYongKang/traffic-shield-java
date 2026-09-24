package com.github.highcumontoa.trafficshieldjava.config;

import com.github.highcumontoa.trafficshieldjava.service.TrafficShieldService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * 防护层装配：开启配置属性绑定与调度，并注册限流窗口清理任务。
 * 其余组件（TrafficShieldService / ShieldController 等）通过构造型注解自动注册。
 */
@Configuration
@EnableConfigurationProperties(ShieldProperties.class)
@EnableScheduling
public class ShieldConfig {

    private final TrafficShieldService service;

    public ShieldConfig(TrafficShieldService service) {
        this.service = service;
    }

    /**
     * 定期清理限流器中已过期的计数窗口。间隔可由
     * {@code traffic-shield.sweep-interval-seconds} 配置（默认 10 秒）。
     */
    @Scheduled(fixedDelayString = "#{${traffic-shield.sweep-interval-seconds:10} * 1000}")
    public void sweepRateLimitWindows() {
        service.sweepWindows();
    }
}

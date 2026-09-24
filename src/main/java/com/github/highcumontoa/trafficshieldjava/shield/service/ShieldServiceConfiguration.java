package com.github.highcumontoa.trafficshieldjava.shield.service;

import com.github.highcumontoa.trafficshieldjava.shield.config.DefaultRules;
import com.github.highcumontoa.trafficshieldjava.shield.config.ShieldConfig;
import com.github.highcumontoa.trafficshieldjava.shield.ratelimit.RateLimiter;
import com.github.highcumontoa.trafficshieldjava.shield.security.SecurityInspector;
import com.github.highcumontoa.trafficshieldjava.shield.stats.ShieldStats;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 装配防护组件。
 */
@Configuration
public class ShieldServiceConfiguration {

    @Bean
    public ShieldStats shieldStats() {
        return new ShieldStats();
    }

    @Bean
    public ShieldConfig shieldConfig() {
        return DefaultRules.defaultConfig();
    }

    @Bean
    public SecurityInspector securityInspector() {
        return new SecurityInspector();
    }

    @Bean
    public RateLimiter rateLimiter() {
        return new RateLimiter();
    }

    @Bean
    public ShieldService shieldService(ShieldConfig config,
                                       SecurityInspector inspector,
                                       RateLimiter rateLimiter,
                                       ShieldStats stats) {
        return new ShieldService(config, inspector, rateLimiter, stats);
    }
}

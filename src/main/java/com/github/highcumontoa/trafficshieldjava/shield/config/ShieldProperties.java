package com.github.highcumontoa.trafficshieldjava.shield.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * traffic.shield.* 配置项。
 */
@Component
@ConfigurationProperties(prefix = "traffic.shield")
public class ShieldProperties {

    private boolean enabled = true;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}

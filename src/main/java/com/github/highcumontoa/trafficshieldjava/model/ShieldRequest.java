package com.github.highcumontoa.trafficshieldjava.model;

import java.util.Map;

/**
 * 进入防护层的请求特征（与具体入口协议无关的统一抽象）。
 */
public record ShieldRequest(String method,
                            String path,
                            String query,
                            Map<String, String> headers,
                            String body,
                            String source) {
}

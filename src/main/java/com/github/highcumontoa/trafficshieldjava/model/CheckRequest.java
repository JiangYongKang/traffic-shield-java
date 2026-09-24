package com.github.highcumontoa.trafficshieldjava.model;

import java.util.Map;

/**
 * /shield/check 入口的 JSON 请求体。
 */
public record CheckRequest(String method,
                           String path,
                           String query,
                           Map<String, String> headers,
                           String body,
                           String source) {
}

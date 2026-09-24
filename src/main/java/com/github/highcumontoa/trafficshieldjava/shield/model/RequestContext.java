package com.github.highcumontoa.trafficshieldjava.shield.model;

import java.util.List;
import java.util.Map;

/**
 * 从入站请求中提取的、用于检测与限流的特征视图。
 */
public record RequestContext(String source,
                             String method,
                             String path,
                             String rawQuery,
                             Map<String, List<String>> headers,
                             String body) {
}

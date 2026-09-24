package com.github.highcumontoa.trafficshieldjava.shield.model;

import java.util.regex.Pattern;

/**
 * 一条安全检测规则。
 *
 * @param id      稳定的规则标识
 * @param reason  命中后的拒绝原因
 * @param pattern 检测正则
 * @param urlOnly true 表示仅对 path/query 等 URL 组件生效；false 表示对全部特征生效
 */
public record SecurityRule(String id, RejectReason reason, Pattern pattern, boolean urlOnly) {
}

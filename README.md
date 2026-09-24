# Traffic Shield（本地可验证的请求防护与限流）

一套基于内存状态模拟网关的入站流量检查与处置能力。正常流量、可疑流量与超限流量
在所有受防护入口（`/api/**`）下经过同一条判定链，得到**一致且可解释**的结论。

- 技术栈：Spring Boot 3.4 / Java 21 / JUnit 5，无外部中间件
- 判定链：`安全检测 → 限流 → 放行`，每一步都记录统计并打印判定依据

---

## 1. 总体结构

```
shield/
├── model/        判定模型：Decision / RejectReason / ShieldResult / 规则 / 请求视图
├── security/     SecurityInspector：注入、穿越、异常编码检测
├── ratelimit/    RateLimiter + CounterWindow：按来源+规则的固定窗口限流
├── stats/        ShieldStats：命中/拒绝/限流统计（一致快照）
├── config/       ShieldConfig 快照、RuleValidator、内置默认规则、配置项
├── service/      ShieldService：判定门面 + 配置原子更新
└── web/          ShieldFilter、AdminController（管理）、DemoController（受防护入口）
```

处理流程：

```
HTTP 请求
  └─ ShieldFilter（仅 /api/**）
       ├─ 缓存请求体、提取 source/method/path/query/headers/body
       ├─ ShieldService.check()  ← 读取一份 volatile 配置快照
       │     1) SecurityInspector 命中 → REJECT_SECURITY（403）
       │     2) RateLimiter 超限      → REJECT_RATE_LIMIT（429 + Retry-After）
       │     3) 否则                  → ALLOW（进入控制器）
       └─ ShieldStats 同步记录总数 / 放行 / 安全拒绝 / 限流 / 按原因明细
```

---

## 2. 安全检测规则

对以下特征做检测：**原始 path/query、一次 URL 解码、二次 URL 解码**（识别双重编码绕过），
以及 `User-Agent / Referer / Cookie / X-Forwarded-For / X-Real-IP` 等请求头与请求体。

规则按固定优先级顺序评估，命中**第一个**规则即返回，保证拒绝原因稳定、可区分：

| 规则 ID | 拒绝原因（RejectReason） | 作用范围 | 说明 |
|---|---|---|---|
| `SEC-ENCODING-001` | `MALFORMED_ENCODING` | 仅 URL | `%` 后未跟随两个十六进制字符（非法百分号编码） |
| `SEC-ENCODING-002` | `MALFORMED_ENCODING` | 仅 URL | 空字节 `%00` / `\x00` / `\u0000` |
| `SEC-PATH-001` | `PATH_TRAVERSAL` | 仅 URL | `../`、`..\` 或以 `..` 结尾（含 `%2e%2e%2f`、双重编码） |
| `SEC-SQLI-001` | `SQL_INJECTION` | 全部 | 引号闭合后的恒真/恒假，如 `' or '1'='1` |
| `SEC-SQLI-002` | `SQL_INJECTION` | 全部 | `UNION SELECT`（容忍空白与 `/**/` 分隔） |
| `SEC-SQLI-003` | `SQL_INJECTION` | 全部 | `; DROP/TRUNCATE TABLE`、注释结尾 `--`/`#` |
| `SEC-SQLI-004` | `SQL_INJECTION` | 全部 | 时间盲注 `sleep(`/`benchmark(`/`WAITFOR DELAY`、`information_schema` |
| `SEC-XSS-001` | `XSS_ATTEMPT` | 全部 | `<script>` 标签 |
| `SEC-XSS-002` | `XSS_ATTEMPT` | 全部 | `<iframe / <img / <svg / <on...` 危险标签 |
| `SEC-XSS-003` | `XSS_ATTEMPT` | 全部 | 事件处理器 `onerror=` / `javascript:` 协议 |

设计要点（避免误伤正常流量）：

- 编码类规则只作用于 path/query，因此正文中的“进度 100%”不会被误拦；
- 正则均要求明确的攻击形态（引号+布尔表达式、标签尖括号、函数调用等），
  普通文本如 `it's a nice day`、`a-b_c.d`、正常中英文均放行；
- 响应中的 `evidence` 字段给出命中位置（`[query:decoded2]`、`[body]` 等）与匹配片段。

安全命中返回：

```json
HTTP/1.1 403
{
  "status": 403,
  "error": "request_rejected",
  "reason": "SQL_INJECTION",
  "ruleId": "SEC-SQLI-001",
  "evidence": "[query:decoded] ' or '1'='1",
  "retryable": false
}
```

---

## 3. 限流语义

- 算法：**固定时间窗口**（fixed window）。
- 维度：`(限流规则 id, 来源 source)`。来源依次取
  `X-Forwarded-For` 最左地址 → `X-Real-IP` → TCP 对端地址。
- 默认规则（窗口 1000ms）：

  | 规则 ID | 入口路径（精确匹配） | 配额 |
  |---|---|---|
  | `RL-HELLO` | `/api/hello` | 10 次 / 秒 / 来源 |
  | `RL-SUBMIT` | `/api/submit` | 5 次 / 秒 / 来源 |

并发正确性保证：

- 每个 key 拥有独立的 `CounterWindow` 和**分段锁**，
  “窗口是否到期 → 是否放行 → 计数自增”在同一把锁内完成，
  突发/并发下**计数不丢失、不重复放行**；
- 只有当 `now - windowStart >= windowMillis` 时才开新窗口，
  限制**绝不会提前解除**（已由 `t0+999 拒绝、t0+1000 放行` 的测试固定）；
- 不同来源各自拥有独立窗口，互不影响；
- 过期窗口在限流发生时惰性清理，避免内存无限增长。

限流命中返回（含可重试提示）：

```json
HTTP/1.1 429
Retry-After: 1
X-Retry-After-Ms: 899
{
  "status": 429,
  "error": "rate_limited",
  "reason": "RATE_LIMITED",
  "ruleId": "RL-HELLO",
  "evidence": "count=10/10",
  "retryable": true,
  "retryAfterMs": 899
}
```

---

## 4. 规则更新与状态查询

- `GET /shield/rules`：查看当前生效规则。
- `PUT /shield/rules`：整体替换规则。请求体即一份 `ShieldConfig`：

  ```json
  {
    "securityRules": [
      {"id":"SEC-X","reason":"XSS_ATTEMPT","pattern":"<script","urlOnly":false}
    ],
    "rateLimitRules": [
      {"id":"RL-HELLO","pathPattern":"/api/hello","limit":2,"windowMillis":1000}
    ]
  }
  ```

  - 先经 `RuleValidator` 全量校验，**非法规则返回 400 且原规则完全保留**
    （空/重复 id、空表达式、配额 ≤ 0、窗口 ≤ 0、路径重复等均拒绝）；
  - 校验通过后在同一同步块内整体替换 `volatile` 配置引用。
    每次 `check` 开始时只取一次快照，安全规则与限流规则都来自该快照，
    **更新过程中不会出现新旧规则混合判定**；更新同时重置限流计数。
- `GET /shield/stats`：返回一致的统计快照：

  ```json
  {
    "total": 11, "allowed": 8, "rejected": 1, "rateLimited": 2,
    "rejectedByReason": {"SQL_INJECTION": 1, "RATE_LIMITED": 2}
  }
  ```

  所有读写在同一把锁上进行，恒满足 `total = allowed + rejected + rateLimited`。
- `/shield/**` 自身不经过防护过滤器，避免被限流后无法查询/恢复。

---

## 5. 配置项（`src/main/resources/application.properties`）

| 配置键 | 默认值 | 说明 |
|---|---|---|
| `traffic.shield.enabled` | `true` | 是否启用防护过滤器；`false` 时 `/api/**` 直接放行 |
| `server.port` | `8080` | 服务端口 |
| `logging.level....shield` | `INFO` | 防护包日志级别，打印请求特征与判定依据 |

默认规则在 `config/DefaultRules.java` 中以代码方式给出（类型安全、可单测）；
运行期可通过 `PUT /shield/rules` 覆盖。

---

## 6. 验证方法

### 6.1 单元/集成测试

```bash
mvn test
```

覆盖（共 20 个用例）：

| 测试类 | 覆盖点 |
|---|---|
| `SecurityInspectorTest` | 正常请求不误伤；异常编码/穿越(含双重编码)/SQL 注入/XSS 命中；四类拒绝原因两两可区分 |
| `RateLimiterTest` | 50 线程 × 4 次并发突发，放行数**恰好**=配额 100；来源隔离；窗口边界不提前解除；retryAfter 提示 |
| `ShieldServiceTest` | 非法规则抛异常且保留原配置；合法更新原子生效（配额收紧）；统计分项与总数自洽 |
| `ShieldFilterIntegrationTest` | 200/403/429 状态码、响应字段、`Retry-After`、不同入口结论一致 |
| `AdminApiTest` | 非法更新 HTTP 400 且规则字节级不变；统计快照可查 |

测试日志会打印每个请求的特征（method/path/query/body）与判定依据（ruleId/reason/evidence）。

### 6.2 本地手工验证

```bash
mvn spring-boot:run                                 # 默认 8080；如端口被占用：
mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=18080"

# 正常流量（200）
curl 'http://127.0.0.1:8080/api/hello?name=Vincent'

# SQL 注入（403, SQL_INJECTION）
curl 'http://127.0.0.1:8080/api/hello?name=admin%27%20or%20%271%27=%271'

# 双重编码路径穿越（403, PATH_TRAVERSAL）
curl 'http://127.0.0.1:8080/api/hello?next=%252e%252e%252fetc/passwd'

# 异常编码（403, MALFORMED_ENCODING）
curl 'http://127.0.0.1:8080/api/hello?name=%zz'

# XSS（403, XSS_ATTEMPT）
curl -X POST 'http://127.0.0.1:8080/api/submit' -H 'Content-Type: application/json' \
     -d '{"comment":"<script>alert(1)</script>"}'

# 限流（前 10 次 200，之后 429 且带 Retry-After）
for i in $(seq 1 12); do
  curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 10.0.0.8' \
       'http://127.0.0.1:8080/api/hello'
done

# 查询统计 / 规则
curl 'http://127.0.0.1:8080/shield/stats'
curl 'http://127.0.0.1:8080/shield/rules'

# 非法规则更新（400，原规则保留）
curl -X PUT 'http://127.0.0.1:8080/shield/rules' -H 'Content-Type: application/json' -d '{
  "securityRules": [],
  "rateLimitRules": [{"id":"BAD","pathPattern":"/api/hello","limit":0,"windowMillis":1000}]
}'
```

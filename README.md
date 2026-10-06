# traffic-shield-java

本地可验证的请求防护与限流能力（内存状态模拟网关）。所有入口共用同一个无状态判定编排方法，
因此正常流量、可疑流量与超限流量在不同入口下都会得到**一致且可解释**的结论。

- 安全检测：SQL 注入、XSS、命令注入、路径穿越、异常编码，命中即拒绝并返回稳定、可区分的原因码。
- 按来源 + 规则限流：固定时间窗口计数，突发/并发下计数精确，不丢计数、不重复放行、不提前解除。
- 来源分级配额：按来源重要程度分档（如内部/普通外部/需收紧），每档独立额度与窗口，
  同一请求只按命中档位计一次，档位间互不影响，未命中档位回退普通限流规则。
- 误拦例外：按 (来源, 路径) 维度豁免指定签名规则，放行业务误拦流量；
  内置异常编码检查（明显攻击特征）不可豁免，例外不会放过明显攻击。
- 状态容量治理：内存中保留的限流状态有明确上限，超限先清过期、再按 LRU 回收；
  被回收来源在窗口仍有效时再次出现会恢复原计数，同一窗口内不会凭空多放行。
- 规则原子更新：安全规则/限流规则/分级档位/误拦例外四部分整表校验通过后一次性发布，
  更新期间不混合新旧规则；任一部分非法整体拒绝，旧规则保留。
- 统计查询：命中/拒绝/限流计数在同一锁下采样，`total = 放行 + 安全拒绝(各类之和) + 限流` 恒成立。
- 测试覆盖正常、可疑、并发超限、更新并发、分级配额、误拦例外与容量回收场景，
  日志打印请求特征与判定依据。

## 1. 判定结论（统一响应体）

所有入口返回同一结构：

| 字段 | 含义 |
| --- | --- |
| `allowed` | 是否放行 |
| `status` | `ALLOW` / `REJECT` |
| `reason` | 稳定原因码，见下表 |
| `ruleId` | 命中的规则 ID（放行时为 null） |
| `message` | 人类可读的判定依据（含命中文段、原始/解码视图、匹配片段） |
| `retryAfterSeconds` | 仅限流：建议多少秒后重试 |
| `rulesVersion` | 判定时生效的规则版本 |
| `source` / `path` | 来源与路径，便于自解释 |

### 拒绝原因码（稳定、可区分）

| reason | 触发条件 | HTTP 状态（网关入口） |
| --- | --- | --- |
| `SQL_INJECTION` | SQL 注入签名（注释符、UNION、堆叠/布尔注入、危险关键字等） | 403 |
| `XSS` | `<script>`、事件属性、`javascript:`、危险标签等 | 403 |
| `COMMAND_INJECTION` | shell 连接符 + 命令、命令替换、危险系统命令 | 403 |
| `PATH_TRAVERSAL` | `../`、`..\`、敏感系统路径等（含 URL 解码后识别） | 403 |
| `SUSPICIOUS_ENCODING` | 畸形百分号、双重编码危险片段、空字节、`%uXXXX`、UTF-8 超长编码 | 403 |
| `RATE_LIMITED` | 超过来源在规则窗口内的配额 | 429（带 `Retry-After`） |
| `ALLOWED` | 未命中安全规则且未超限 | 200 |

## 2. 检测规则

安全检测对 `path`、`query`、业务可写请求头（`Referer` 与 `X-*`，不含 `Accept`/`User-Agent`/`Cookie`
等基础设施头）、`body` 依次扫描，分两个阶段：

1. **异常编码（内置 ENC-* 检查）**
   - `ENC-MALFORMED-PERCENT`：URL 字段中 `%` 后不是两位十六进制（仅 path/query 判定，避免误伤 "100% 满意" 类正文）；
   - `ENC-DOUBLE-ENCODED`：双重编码危险片段（如 `%252e%252e%252f`）；
   - `ENC-NULL-BYTE`：`%00` / 空字节；
   - `ENC-PERCENT-U`：非标准 `%uXXXX`（仅 URL 字段）；
   - `ENC-OVERLONG-UTF8`：UTF-8 超长编码如 `%c0%af`（仅 URL 字段）。
2. **签名匹配（可更新的正则规则表，大小写不敏感 + DOTALL）**
   在原始文本与 URL 解码后文本上各匹配一次，按规则声明顺序取**首个命中**。
   默认规则 17 条，ID 形如 `SQL-00x` / `XSS-00x` / `CMD-00x` / `PATH-00x` / `ENC-*`，
   完整内容见 `security/DefaultRules.java`。规则设计保守，正常查询、合法百分号编码、
   `2-1`、`10:00`、`*/*` 等正常文本均不会被误拦。

> 说明：路径字面量中的 `../` 会被 Tomcat 等容器在到达应用前归一化，因此真实的穿越特征通常
> 出现在 query/body（如文件名参数），本系统在这些位置（解码前后）稳定识别。

## 3. 限流语义

- 维度：**(来源, 限流规则)** 各自独立的固定时间窗口；规则按路径的 Ant 模式（如 `/**`）匹配，
  一个请求只被第一条匹配的规则计数。
- 窗口：从该来源该规则的首个请求时刻起算 `windowSeconds` 秒；窗口内第 `1..limit` 个请求放行，
  第 `limit+1` 个起返回 `RATE_LIMITED`；**窗口未结束绝不提前解除**，越过边界后下一个请求开启新窗口。
- 并发：每个窗口用 `AtomicLong` 计数（自增即计数、不回滚），前 `limit` 次自增必然放行、其后必然拒绝；
  窗口切换用 CAS 替换窗口对象、竞争失败取最新窗口重试，保证 500 并发/配额 50 时精确放行 50。
- 来源识别：优先取 `traffic-shield.source-header` 指定的头（`X-Forwarded-For` 取第一个），
  缺省回退对端 IP；JSON 入口可显式传 `source`。
- 可重试：429 响应带 `Retry-After` 头与体内 `retryAfterSeconds`（距窗口结束的秒数，最少 1）。
- 内存：过期窗口由定时任务（默认每 10s）清理；状态总量另有容量上限，见「状态容量治理」。
- 顺序：**先安全检测后限流**，被安全拒绝的请求不消耗限流配额。

### 3.1 来源分级配额

所有来源共用一个额度不够用时，可通过 `tierRules` 把来源分成几档，每档独立额度与窗口：

```json
{ "id": "TIER-INTERNAL",   "sourcePattern": "internal-*", "pathPattern": "/**", "limit": 100, "windowSeconds": 10 }
{ "id": "TIER-RESTRICTED", "sourcePattern": "ext-*",      "pathPattern": "/**", "limit": 2,   "windowSeconds": 10 }
```

- 匹配：按档位声明顺序，**首个** `sourcePattern`（Ant 风格，匹配来源）与 `pathPattern`
  （匹配路径）同时命中的档位生效；一个请求只按该档位**计一次数**。
- 隔离：每个 (来源, 档位) 独立固定窗口，不同档位、不同来源互不影响。
- 回退：未命中任何档位的请求走普通 `rateLimitRules`；`tierRules` 为空列表等同未启用分级，
  行为与旧版本完全一致（兼容范围：不配置分级时无任何行为变化）。
- 生效方式：与规则更新同一机制整表替换、原子发布，并发判定期间不会新旧档位混用；
  非法档位（空 id、重复 id、空模式、非正 limit/windowSeconds）整次更新拒绝，旧档位保留。

### 3.2 状态容量治理

来源基数高时，内存中的限流状态有明确上限与回收策略：

- 上限：`traffic-shield.max-state-entries`（默认 10000），约束保留的窗口状态数量。
- 回收策略：超限（或定时清理）时**先删除已过期窗口**；仍超限则按 **LRU（最久未使用）**
  回收活跃窗口。判定期内联触发与定时任务清理可并发执行，只使用并发容器原子操作，
  用户侧不会看到偶发报错，放行/拒绝结论不会前后矛盾。
- 回收语义（墓碑恢复）：被 LRU 回收的活跃窗口不丢弃，而是**同一对象整体移入墓碑区**
  （计数原样保留）。该来源在**同一有效窗口**内再次出现时，通过 `compute` 原子恢复原窗口
  继续计数——配额语义等同从未被回收，**不会凭空多放行**；窗口已自然过期的墓碑不参与恢复，
  由清理直接移除。墓碑区同样受容量上限约束，超出时先清过期、再淘汰最旧。

## 4. 误拦例外

上线后若正常业务请求被某条签名规则误拦，运营侧可配置 `allowlistExceptions` 放行确属正常的流量：

```json
{ "id": "EX-PARTNER", "sourcePattern": "partner-*", "pathPattern": "/api/orders",
  "exemptRuleIds": ["SQL-003"] }
```

- 匹配维度：`sourcePattern` / `pathPattern`（Ant 风格，`null` 表示该维度不限制，但不能同时为 `null`）。
- 作用范围：命中例外后，仅 `exemptRuleIds` 列出的**签名规则**对该请求不再生效
  （视为未命中，继续检查其余规则）；未列出的规则、非匹配的来源/路径不受影响。
- 安全边界：内置异常编码检查（ENC-*：双重编码、空字节、畸形百分号等**明显攻击特征**）
  不是签名规则，**任何例外都不能豁免**，也无法被配置为豁免目标（其 id 不在安全规则表中，
  配置即非法）。因此配了例外也不会放过明显攻击请求。
- 校验与生效：与规则更新同一机制整体校验、原子发布。非法例外（空 id、重复 id、
  两个维度同时为空、豁免列表为空、引用了不存在的规则 id）导致**整次更新被拒绝**，
  旧例外配置保留，生效前后判定结果不会忽好忽坏。

## 5. 规则更新与一致性

- 规则与编译结果打包为不可变节点 `ActiveRules`，通过一个 `AtomicReference` 原子发布；
  一次请求只读取一次该引用，安全规则、限流规则、分级档位、误拦例外与版本号来自同一对象，
  **更新期间不可能新旧混用**（测试中 200 轮更新 + 16000 次并发判定 0 违例）。
- 更新是"整表替换"：`securityRules` / `rateLimitRules` / `tierRules` / `allowlistExceptions`
  四个字段为 `null` 表示该部分不变，非 `null` 表示整表替换（空列表表示清空/关闭该能力）。
  四个部分**全有或全无**：任何一条规则非法（空 ID、重复 ID、非法 category、非法正则、
  非正的 limit/windowSeconds、豁免不存在的规则等）都会整体拒绝并返回 400，
  旧规则与版本保持不变。

## 6. 配置项（`src/main/resources/application.properties`）

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `traffic-shield.enabled` | `true` | 安全检测总开关（关闭后仅限流） |
| `traffic-shield.default-limit` | `10` | 内置默认限流规则的每窗口配额 |
| `traffic-shield.default-window-seconds` | `10` | 内置默认限流窗口长度（秒） |
| `traffic-shield.source-header` | `X-Forwarded-For` | 来源识别请求头 |
| `traffic-shield.sweep-interval-seconds` | `10` | 过期窗口清理与容量回收间隔（秒） |
| `traffic-shield.max-state-entries` | `10000` | 限流状态容量上限（超限先清过期、再 LRU 回收） |

## 7. HTTP 接口

| 方法与路径 | 说明 |
| --- | --- |
| `ANY /gateway/**` | 模拟网关入口：200 放行 / 403 安全拒绝 / 429 限流 |
| `POST /shield/check` | JSON 检查入口，提交请求特征，始终返回 200，结论在响应体内 |
| `GET /shield/rules` | 查询当前生效规则与版本 |
| `PUT /shield/rules` | 原子更新规则（非法返回 400，旧规则保留） |
| `GET /shield/stats` | 统计快照 |

`/shield/check` 请求体示例：

```json
{ "method": "GET", "path": "/products", "query": "id=1 OR 1=1",
  "headers": { "X-Trace": "t-1" }, "body": null, "source": "user-42" }
```

## 8. 本地验证

```bash
# 全部单测（33 个：正常/可疑/单线程限流/500并发/更新并发/双入口一致性/统计/
# 分级配额/误拦例外/容量回收并发），日志可见各用例覆盖的业务与结果
mvn test

# 启动应用
mvn spring-boot:run
```

启动后：

```bash
B=http://localhost:8080

# 正常 => 200 ALLOWED
curl -s -H 'X-Forwarded-For: u1' "$B/gateway/api/orders?page=2"

# SQL 注入 => 403 SQL_INJECTION
curl -s -H 'X-Forwarded-For: u1' "$B/gateway/products?id=1%20OR%201=1"

# 路径穿越（参数位）=> 403 PATH_TRAVERSAL
curl -s -G -H 'X-Forwarded-For: u1' "$B/gateway/files" --data-urlencode 'name=../../etc/passwd'

# 双重编码 => 403 SUSPICIOUS_ENCODING
curl -s -H 'X-Forwarded-For: u1' "$B/gateway/files?name=%252e%252e%252fetc"

# 突发限流（默认 10/10s）：前 10 次 200，之后 429 + Retry-After
for i in $(seq 1 12); do
  curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: burst' "$B/gateway/api/x"
done

# JSON 检查入口（与网关入口结论一致）
curl -s -X POST "$B/shield/check" -H 'Content-Type: application/json' \
  -d '{"path":"/products","query":"id=1 OR 1=1","source":"u1"}'

# 规则查询 / 原子更新 / 统计
curl -s "$B/shield/rules"
curl -s -X PUT "$B/shield/rules" -H 'Content-Type: application/json' \
  -d '{"securityRules":[{"id":"CUSTOM-1","name":"自定义禁词","category":"XSS","pattern":"forbidden-token"}]}'
curl -s "$B/shield/stats"

# 来源分级配额：internal-* 每 10s 100 次，ext-* 每 10s 2 次，其余来源走默认规则
curl -s -X PUT "$B/shield/rules" -H 'Content-Type: application/json' -d '{
  "tierRules": [
    {"id":"TIER-INTERNAL","sourcePattern":"internal-*","pathPattern":"/**","limit":100,"windowSeconds":10},
    {"id":"TIER-RESTRICTED","sourcePattern":"ext-*","pathPattern":"/**","limit":2,"windowSeconds":10}
  ]}'
# ext-1 第 3 次请求即 429（ruleId=TIER-RESTRICTED），internal-1 不受影响
for i in $(seq 1 3); do
  curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: ext-1' "$B/gateway/api/x"
done

# 误拦例外：partner-* 在 /api/orders 上豁免 SQL-003，正常业务查询放行；
# 双重编码等明显攻击仍 403
curl -s -X PUT "$B/shield/rules" -H 'Content-Type: application/json' -d '{
  "allowlistExceptions": [
    {"id":"EX-PARTNER","sourcePattern":"partner-*","pathPattern":"/api/orders","exemptRuleIds":["SQL-003"]}
  ]}'
curl -s -X POST "$B/shield/check" -H 'Content-Type: application/json' \
  -d '{"path":"/api/orders","query":"filter=status%20or%201=1","source":"partner-1"}'
curl -s -X POST "$B/shield/check" -H 'Content-Type: application/json' \
  -d '{"path":"/api/orders","query":"name=%252e%252e%252fetc","source":"partner-1"}'
```

## 9. 代码结构

```
model/        请求/结论/规则/分级档位/误拦例外/统计等不可变模型与稳定原因码枚举
security/     默认规则库、规则与例外的校验编译、无状态安全检测（例外不豁免内置编码检查）
ratelimit/    按来源+规则/档位的固定窗口并发安全限流器（容量上限 + LRU 回收 + 墓碑恢复）
service/      ActiveRules 原子发布节点 + 编排服务（安全→限流→统计）
config/       配置属性、Bean 装配与过期窗口清理/容量回收调度
web/          网关入口、JSON 检查入口、管理面接口与全局异常处理
```

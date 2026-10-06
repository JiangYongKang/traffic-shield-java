# traffic-shield-java

本地可验证的请求防护与限流能力（内存状态模拟网关）。所有入口共用同一个无状态判定编排方法，
因此正常流量、可疑流量与超限流量在不同入口下都会得到**一致且可解释**的结论。

- 安全检测：SQL 注入、XSS、命令注入、路径穿越、异常编码，命中即拒绝并返回稳定、可区分的原因码。
- 按来源 + 规则限流：固定时间窗口计数，突发/并发下计数精确，不丢计数、不重复放行、不提前解除。
- 来源分级配额：按来源重要程度分档（内部/普通外部/收紧），每档独立额度与窗口，
  一个请求只按首个命中档计一次数，档位之间互不影响。
- 误拦例外：按 （来源， 路径） 配置例外豁免可配置签名规则；内置的明显攻击编码检查不受例外影响。
- 状态容量治理：限流状态条目有明确上限与回收策略（先过期、再降级影子、最后硬删影子），
  被回收来源在同一有效窗口内重现不会凭空多放行。
- 规则原子更新：整表校验通过后一次性发布，更新期间不混合新旧规则；非法规则被拒绝，旧规则保留。
- 统计查询：命中/拒绝/限流计数在同一锁下采样，`total = 放行 + 安全拒绝(各类之和) + 限流` 恒成立。
- 测试覆盖正常、可疑、并发超限与更新并发场景，日志打印请求特征与判定依据。

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
- 内存：过期窗口由定时任务（默认每 10s）清理；状态总量另有容量上限治理，见第 4.2 节。
- 顺序：**先安全检测后限流**，被安全拒绝的请求不消耗限流配额；
  限流内部先扣分级档位配额、再扣路径规则配额，被档位限流的请求不再消耗路径规则配额。

## 4.1 来源分级配额

不同重要程度的来源共用同一个额度不够用时，可以把来源分成几档，每档单独设额度和窗口。

- 配置：规则集中的 `quotaTiers` 整表，每档形如
  `{ "id": "TIER-INTERNAL", "sourcePattern": "internal-*", "limit": 100, "windowSeconds": 60 }`，
  `sourcePattern` 为 Ant 风格（来源字符串没有路径分隔符，`*` 即可匹配任意后缀）。
- 命中语义：按档位表**声明顺序**取**首个** `sourcePattern` 命中请求来源的档位，
  一个请求只按这一档计一次数；未命中任何档位的来源不受分级配额约束。
  各档位的计数窗口互相独立，一档超限不影响其他档位，也不影响路径限流规则。
- 生效方式：与安全/限流规则一样通过 `PUT /shield/rules` 的 `quotaTiers` 字段**整表替换**，
  随同一个新版本原子发布——并发请求期间不会出现一部分按老档位、一部分按新档位判定的情况。
- 校验：档位 id 非空且唯一、`sourcePattern` 非空、`limit`/`windowSeconds` 为正整数；
  任何一条非法则整个更新被拒绝（400），旧档位表与版本保持不变。
- 限流响应：被档位限流时 `reason=RATE_LIMITED`、`ruleId` 为档位 id，同样带 `retryAfterSeconds`。

## 4.2 限流状态容量治理

来源基数一高，内存里的计数状态会持续上涨，因此给保留的状态一个明确上限与回收策略。

- 上限：`traffic-shield.max-state-entries`（默认 10000）。状态分两类，**各自**不超过该上限
  （总预算即 2 倍上限）：存活窗口（正在接受计数）与回收影子（被回收窗口的只读计数记录）。
- 回收策略（超限后严格按序执行）：
  1. 先删除窗口已经结束的过期条目（两类都删）；
  2. 存活窗口仍超限，则把**窗口开始时间最早**的存活窗口**降级为影子**——
     存活窗口只降级、绝不直接硬删，计数不丢；
  3. 影子空间不足时，先删过期影子，再按开始时间最早优先**硬删影子**。
     只有走到这一步，对应来源的窗口计数才真正丢失。
- 配额连续性：被降级为影子的来源在**同一个仍有效的窗口**内再次出现时，从影子恢复原窗口
  **继续计数**（降级/恢复共享同一个计数器），不会凭空多获得配额；窗口结束后影子随过期清理
  一并删除，来源按新窗口重新计数。影子预算也被占满的极端压力下，来源按新窗口处理
  （宁可放行也不让内存失控），这是明确记录的取舍。
- 并发安全：回收只使用条件删除/条件替换，与正常判定、定时清理并发执行不会抛错；
  判定结论只取决于共享计数器与阈值的比较，不会因回收而前后矛盾。

## 4.3 误拦例外

正常业务请求被安全签名误拦时，运营侧可以配置例外把确属正常的流量放出去。

- 配置：规则集中的 `allowlistExceptions` 整表，每条例外形如
  `{ "id": "EX-CMS-TEMPLATE", "sourcePattern": "cms-*", "pathPattern": "/api/templates" }`，
  **来源与路径两个维度同时命中**（Ant 风格）才生效。
- 安全边界：例外只豁免**可配置签名规则**（SQL/XSS/CMD/PATH 等正则规则表）；
  内置的明显攻击编码检查（`ENC-*`：双重编码、空字节、畸形百分号、`%uXXXX`、UTF-8 超长编码）
  **不受例外影响**，因此配了例外也不会把明显的攻击请求一起放过。
  例外之外的来源/路径仍按原规则判定。
- 生效方式：与规则一样通过 `PUT /shield/rules` 的 `allowlistExceptions` 字段**整表替换**、
  原子发布，生效前后判定结果不会忽好忽坏。
- 校验：例外 id 非空且唯一、`sourcePattern`/`pathPattern` 非空；
  任何一条非法则整个更新被拒绝（400），旧例外表与版本保持不变。

## 4.4 规则更新与一致性

- 规则与编译结果打包为不可变节点 `ActiveRules`，通过一个 `AtomicReference` 原子发布；
  一次请求只读取一次该引用，安全规则、限流规则、版本号来自同一对象，**更新期间不可能新旧混用**
  （测试中 200 轮更新 + 16000 次并发判定 0 违例）。
- 更新是"整表替换"：`securityRules` / `rateLimitRules` / `quotaTiers` / `allowlistExceptions`
  字段为 `null` 表示该部分不变，非 `null` 表示整表替换。任何一条规则非法（空 ID、重复 ID、
  非法 category、非法正则、非正的 limit/windowSeconds、空匹配模式等）都会整体拒绝并返回 400，
  旧规则与版本保持不变。

## 5. 配置项（`src/main/resources/application.properties`）

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `traffic-shield.enabled` | `true` | 安全检测总开关（关闭后仅限流） |
| `traffic-shield.default-limit` | `10` | 内置默认限流规则的每窗口配额 |
| `traffic-shield.default-window-seconds` | `10` | 内置默认限流窗口长度（秒） |
| `traffic-shield.source-header` | `X-Forwarded-For` | 来源识别请求头 |
| `traffic-shield.sweep-interval-seconds` | `10` | 过期限流窗口清理间隔（秒） |
| `traffic-shield.max-state-entries` | `10000` | 限流状态容量上限：存活窗口与回收影子各自不超过该值 |

## 6. HTTP 接口

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

## 7. 本地验证

```bash
# 全部单测（32 个：正常/可疑/单线程限流/500并发/更新并发/双入口一致性/统计/
# 分级配额/误拦例外/状态容量治理）
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

# 来源分级配额：内部档 100/60s、收紧档 2/60s，整表替换立即生效
curl -s -X PUT "$B/shield/rules" -H 'Content-Type: application/json' \
  -d '{"quotaTiers":[{"id":"TIER-INTERNAL","sourcePattern":"internal-*","limit":100,"windowSeconds":60},
                     {"id":"TIER-TIGHT","sourcePattern":"tight-*","limit":2,"windowSeconds":60}]}'
# 收紧档来源：前 2 次 200，第 3 次起 429（ruleId=TIER-TIGHT）
for i in $(seq 1 4); do
  curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: tight-1' "$B/gateway/api/x"
done

# 误拦例外：CMS 后台提交含 <img> 的模板，默认被 XSS-004 拦（403）
curl -s -X POST "$B/shield/check" -H 'Content-Type: application/json' \
  -d '{"method":"POST","path":"/api/templates","body":"{\"t\":\"<img src=/a.png>\"}","source":"cms-1"}'
# 配置 （来源 cms-*，路径 /api/templates） 例外后同一请求放行；
# 但带双重编码等明显攻击特征的请求仍然 403（例外不豁免内置编码检查）
curl -s -X PUT "$B/shield/rules" -H 'Content-Type: application/json' \
  -d '{"allowlistExceptions":[{"id":"EX-CMS","sourcePattern":"cms-*","pathPattern":"/api/templates"}]}'
curl -s -X POST "$B/shield/check" -H 'Content-Type: application/json' \
  -d '{"method":"POST","path":"/api/templates","body":"{\"t\":\"<img src=/a.png>\"}","source":"cms-1"}'
curl -s -H 'X-Forwarded-For: cms-1' "$B/gateway/api/templates?name=%252e%252e%252fetc"
```

## 8. 代码结构

```
model/        请求/结论/规则/分级档位/误拦例外/统计等不可变模型与稳定原因码枚举
security/     默认规则库、规则校验与编译、无状态安全检测、误拦例外匹配
ratelimit/    按来源+规则/档位的固定窗口并发安全限流器（含状态容量治理与影子回收）
service/      ActiveRules 原子发布节点 + 编排服务（例外→安全→档位→限流→统计）
config/       配置属性、Bean 装配与过期窗口清理调度
web/          网关入口、JSON 检查入口、管理面接口与全局异常处理
```

## 9. 兼容范围

- `RuleSet` / `RuleUpdateRequest` 新增 `quotaTiers`、`allowlistExceptions` 字段：
  请求体不传（JSON 中为 `null`）时语义为"该部分保持不变"，旧调用方无需修改；
  代码层面 `RuleUpdateRequest` 保留双参构造（仅安全+限流规则）以兼容旧调用。
- 未配置 `quotaTiers`（空表）时行为与之前完全一致：所有来源只受路径限流规则约束。
- 未配置 `allowlistExceptions`（空表）时安全判定与之前完全一致。
- `traffic-shield.max-state-entries` 缺省 10000，不配置即有容量保护；
  调小该值只会更积极地触发影子降级，不改变单窗口内的配额语义。
- 判定原因码集合不变（`ALLOWED` / 各类安全码 / `RATE_LIMITED`），
  分级档位限流复用 `RATE_LIMITED` 并以 `ruleId` 区分档位与路径规则。

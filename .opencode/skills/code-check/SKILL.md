---
name: code-check
description: "ANS 通知子系统门禁式综合代码检视技能。运行时第一步与用户确认检视维度（支持多选与全量检视），随后对代码变更执行选定维度检视（功能/逻辑/安全/性能/兼容性/DFX/规范/测试/架构），经 Refute 对抗性验证过滤误报后产出统一门禁报告（评分+决策矩阵+refute_log）。触发于：代码检视、深度扫描、全面排查、codecheck、生成检视报告、安全审计、门禁检视、上库前检视等请求。"
---

# Code-Check — ANS 通知子系统门禁式代码检视编排器

## 定位

本技能是通知子系统（ANS，distributed_notification_service）的**门禁式综合代码检视编排器**：
用户确认检视维度后，调度各维度检视指南执行扫描，对全部发现执行 Refute 对抗性验证（过滤误报
与夸大），最终合并为一份带评分与上库决策的统一门禁报告。

**原则**：检视阶段只产出报告与建议，**不直接修改源码**；修复由用户确认后另起任务。

---

## 维度体系（9 维度）

| # | 维度 | 标识 | 检查内容 | 指南 |
|---|---|---|---|---|
| 1 | 功能 | `functionality` | 需求意图对照、行为符合性、边界场景矩阵、特性开关双路径、分布式四场景行为 | [references/functionality-review.md](references/functionality-review.md) |
| 2 | 逻辑 | `logic` | 控制流、数据流、状态机、边界条件、错误处理、并发控制、业务不变性 | [references/logic-analysis.md](references/logic-analysis.md) |
| 3 | 安全 | `security` | 官方安全编程指南全量（内存/指针/整数/资源/标准库）、IPC 输入校验、json 崩溃清单、通知隐私、权限位置 | [references/security-review.md](references/security-review.md) |
| 4 | 性能 | `performance` | 高频路径开销、锁行为、IPC 效率、启动性能、LiveView 频率、分布式流量功耗 | [references/performance-review.md](references/performance-review.md) |
| 5 | 兼容性 | `compatibility` | 公共 API 红线、Parcelable/IDL/js-ets/map 序列化兼容、RDB schema、分布式协议跨版本 | [references/compatibility-review.md](references/compatibility-review.md) |
| 6 | DFX | `dfx` | 官方日志规范全量、客户端禁打点、EventReport 事件、隐私脱敏、HiTrace | [references/dfx-review.md](references/dfx-review.md) |
| 7 | 规范 | `checklist` | C++ 编码规范、64 位可移植、编译选项、版权头、贡献规范、TS/JS、通用陷阱 | [references/checklist.md](references/checklist.md) |
| 8 | 测试 | `test` | 变更-测试映射、用例质量、90% 分支覆盖、IPC Fuzz、安全测试规范 | [references/test-coverage-review.md](references/test-coverage-review.md) |
| 9 | 架构 | `architecture` | 分层依赖、架构不变量、DDD 边界、可测试性（大型变更适用） | [references/architecture-review.md](references/architecture-review.md) |

> **ANS 特有陷阱 A1~A9 全集定义**见 [references/ans-pitfalls.md](references/ans-pitfalls.md)——
> 各维度指南中引用的陷阱编号（A1~A9）均以该文件为唯一权威定义。

---

## 工作流

### Step 0: 确认检视维度（必须最先执行）

**技能被触发后的第一件事**：使用 question 工具向用户确认检视维度（不是所有提交都需要全量检视）。

**问题 1（多选）**：「本次需要执行哪些检视维度？」

| 选项 | 说明 |
|---|---|
| 全量检视（推荐用于上库门禁） | 执行全部 9 个维度 |
| 功能 | 需求实现完整性与行为符合性 |
| 逻辑 | 控制流/数据流/状态机/边界/错误处理 |
| 安全 | 内存/输入校验/权限/敏感信息 |
| 性能 | 高频路径/锁/IPC/启动/功耗 |
| 兼容性 | API/序列化/跨版本/分布式协议 |
| DFX | 日志/打点/Trace 可观测性 |
| 规范 | 编码规范/版权/编译选项/贡献规范 |
| 测试 | 单测/Fuzz 覆盖 |
| 架构 | 分层依赖/架构不变量（大型变更） |

- 选项描述中附场景化建议：功能开发 → 功能+逻辑+规范+测试；对外发布/接口变更 → 安全+兼容+性能；结构性重构 → +架构
- 检视范围为纯文档变更（仅 `.md`/`.yaml` 等非代码文件）时，建议用户仅选择「规范」维度，其余维度按 N/A 处理（不计为缺失）
- 同时选择"全量"与其他维度时，全量生效（超集）
- 用户在原始请求中已明确指定维度时，跳过本问题

**问题 2（条件执行，用户未给范围时必问）**：「检视范围？」

- 当前未提交变更（`git diff HEAD`）
- 指定路径/目录
- 指定 commit 或分支对比（`git diff <base>..<head>`）

**问题 3（可选，功能维度被选中时询问）**：「本次变更对应的需求/任务背景？」（供功能维度对照需求意图；无背景则功能维度按 diff 推断并标注局限）

### Step 1: 界定范围与版本信息

```bash
git rev-parse HEAD                                  # 完整 40 位 commit-id
git log -1 --format="%b" | grep -o 'Change-Id: I[0-9a-f]\{40\}'  # Change-Id
git log -1 --format="%s"                            # commit subject
git diff HEAD --name-only                           # 或用户指定范围的 diff 文件清单
```

必明确三项：**目标**（范围）、**检视重点**（用户意图）、**版本信息**（commit-id/Change-Id，记入报告头部）。
用户只说"检视一下代码"未给范围且问题 2 未获答案时**必须追问**，不要默认全仓。

### Step 2: 特征探测与重点标注

按变更文件路径自动标注重点维度（写入各维度指南的执行提示，不改变用户选定集合）：

| 变更路径 | 重点标注 |
|---|---|
| `frameworks/ans/*.idl`、`frameworks/ans/src/` | 兼容性（IDL 末尾追加、Parcelable 顺序） |
| `interfaces/inner_api/` | 兼容性（API 红线）+ 三层联动（NAPI/NDK） |
| `interfaces/kits/napi/`、`frameworks/js/`、`frameworks/ets/` | 兼容性（js/ets 双套同步） |
| `services/ans/src/advanced_notification_publish/` | 功能+逻辑+性能（高频路径） |
| `services/distributed/` | 功能（四场景）+ 兼容性（协议）+ 安全（跨设备数据） |
| `services/ans/src/disturb_manager/`、`badge_manager/` | 功能（业务语义）+ 逻辑（状态机） |
| `notification.gni` | 功能（开关双路径）+ 规范（条件编译完整） |
| `*.map` | 兼容性（符号冻结红线） |
| `BUILD.gn` | 规范（PAC/栈保护） |
| `frameworks/core/common/` | 全维度提权（公共基础设施，影响面大） |
| `test/` | 测试 |

**静态排除**（非维护目录，出现改动即 P0 上报，不进入维度检视）：
`frameworks/cj/`、`frameworks/reminder/`、`frameworks/reminder_ani/`、`services/reminder/`

### Step 3: 并行调度维度检视

- 仅执行 Step 0 用户选定的维度（= `dimensions_required`）
- 各维度间无数据依赖，**并行执行**（子代理或并发工具调用，单层并发 ≤4，超出则分批）
- 每个维度严格按对应 `references/<dimension>-review.md` 执行
- 保留各维度原始产出，不在中间改写
- 记录每个维度：产出文件路径、发现总数与分级（P0/P1/P2/P3）

### Step 4: 收集各维度原始产出

各维度产出保存至 `.codecheck/raw/<dimension>.md`（发现列表，含编号/位置/触发路径/证据/建议）。

### Step 5: Refute — 对抗性验证

对每条发现执行三层质疑，详细规则见 [references/refute-rules.md](references/refute-rules.md)：

1. **触发路径证伪**："真的能被触发吗？"（上游防护/不可达/常量来源/IPC 暴露面/特性开关）
2. **影响夸大证伪**："后果真的这么严重吗？"（double-free 防护/退出路径回收/UAF 仅日志/数量有界）
3. **跨维度根因去重**："这两个发现是同一根因吗？"（同一修复改动合并/连锁影响合并/独立维持）

产出 `.codecheck/refute_log_{change_id}-R{round}.md`，每条判定：✅维持 | ⬇️降级 | ❌推翻 | 🔀合并。

### Step 6: 合并统一门禁报告

**轮次确定**：`round` = `.codecheck/` 下已有 `codecheck_report_{change_id}-R*.md` 的最大轮次 + 1（首次检视为 1）。产出前先 `mkdir -p .codecheck/raw`。

基于 refute 过滤后的发现，按 [references/report-template.md](references/report-template.md) 生成
`.codecheck/codecheck_report_{change_id}-R{round}.md`。**必须使用权威模板**：

- 头部 **YAML 元数据块**（机器可读，字段/取值域固定）
- **评分公式**：`score = max(0, 100 − (30×P0 + 12×P1 + 5×P2 + 2×P3))`
- **决策矩阵**：选定维度未全部执行 → `insufficient`；有 P0 → `block`；有 P1 → `conditional`；score≥90 → `approve`；score≥70 → `conditional`；否则 `block`
- **部分维度检视标注**：非全量检视时报告头部显式标注"未选维度不在本次结论保障范围内"
- 跨维度去重以 `file:line` 为第一键；YAML 块与第 1 节结论数值必须一致

### Step 7: 交付

向用户交付：

1. 统一报告路径（`.codecheck/codecheck_report_*.md`）
2. Executive Summary：各维度结果、总分、上库决策
3. Top 高危项（P0）及阻塞原因
4. `refute_log` 路径（对抗性验证记录，便于人工复核被推翻项）
5. 各维度原始产出路径（`.codecheck/raw/`）
6. 修复后复检：用户修复后再次触发本技能（Step 0 可沿用上轮维度），`round` 自增；新报告按问题 ID 逐条对比上一轮，标注已闭环 / 未闭环 / 新增

不直接改源码——修复由用户确认后另起任务。

---

## 约定

- **静态排除**：非维护目录（`frameworks/cj/`、`frameworks/reminder/`、`frameworks/reminder_ani/`、`services/reminder/`）默认不检视（出现改动即 P0 上报），除非用户明确要求包含
- **证据要求**：每条发现可追溯到 `file:line` + 触发路径，不收无证据的代码气味项
- **用户指定单一维度**：只执行该维度，其余维度在报告中标注 N/A（不视为缺失，但报告必须带部分检视标注）
- **不动代码**：检视阶段只产出报告与建议
- **Refute 只质疑不发现**：质疑必须有代码证据；P0 推翻需"确认不可达"级证据；被推翻项保留在 refute_log
- **维度无适用面**：该维度仍计入 `dimensions_executed` 并在分维度速览注明 N/A 理由，不计为缺失（如纯文档变更时的安全维度）

## 官方规范溯源总表（本技能已全量内化）

| 官方规范 | 内化落点 | 本地路径（OpenHarmony 全仓） |
|---|---|---|
| C&C++ 安全编程指南 | security-review.md 第一部分 | `docs/zh-cn/contribute/OpenHarmony-c-cpp-secure-coding-guide.md` |
| 安全设计规范 | security-review.md 第二部分 | `docs/zh-cn/contribute/OpenHarmony-security-design-guide.md` |
| 日志打印规范 | dfx-review.md 第一部分 | `docs/zh-cn/contribute/OpenHarmony-Log-guide.md` |
| C++ 语言编程规范 | checklist.md 第一部分 | `docs/zh-cn/contribute/OpenHarmony-cpp-coding-style-guide.md` |
| 32/64 位可移植规范 | checklist.md 第二部分 | `docs/zh-cn/contribute/OpenHarmony-64bits-coding-guide.md` |
| 编译规范 + 开源构建规范 | checklist.md 第三部分 | `docs/zh-cn/contribute/OpenHarmony-compile-rule.md`、`OpenHarmony-build-rule.md` |
| 许可证与版权规范 | checklist.md 第四部分 | `docs/zh-cn/contribute/许可证与版权规范.md` |
| 贡献代码 / 贡献流程 | checklist.md 第五部分 | `docs/zh-cn/contribute/贡献代码.md`、`贡献流程.md` |
| 安全测试规范 | test-coverage-review.md | `docs/zh-cn/contribute/OpenHarmony-security-test-guide.md` |
| TS&JS 编程指南 | checklist.md 第六部分 | `docs/zh-cn/contribute/OpenHarmony-Application-Typescript-JavaScript-coding-guide.md` |
| C 语言 / HDF / Java 规范 | N/A（本仓无对应代码形态，checklist.md 已标注） | — |

各内化检查项均带官方规则编号（如"规则3.1.1"、"G.C&C++.SEC.01"），便于回溯权威源。

## 产出物路径

```
.codecheck/
├── codecheck_report_{change_id}-R{round}.md    # 统一门禁报告
├── refute_log_{change_id}-R{round}.md          # 对抗性验证记录
└── raw/
    └── <dimension>.md                          # 各维度原始发现
```

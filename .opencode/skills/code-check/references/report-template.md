# 统一门禁报告模板 — code-check

> 本模板是 code-check 技能的**唯一报告格式**，用于门禁管控。章节顺序、字段名、报告元数据块、
> 评分与门禁规则均为**固定格式**，跨报告保持一致，便于门禁脚本解析与历史对比。
> 生成入口：SKILL.md Step 6；合并逻辑：先跨维度按 `file:line` 去重，再按本模板填充。
> 生成时必须按本文件末尾的评分与门禁决策矩阵计算，不得自创分值。

---

## 报告元数据（YAML 块）

> **门禁脚本只读取本 YAML 块**。字段名与取值域为固定合约，禁止改名、增删字段或自定义取值。
> 人工阅读部分从「1. 门禁结论」开始。

<!-- codecheck-report-metadata:start -->
```yaml
codecheck_report:
  schema_version: "1.0"
  scope: "{scope}"                      # 检视范围描述（路径/分支/commit）
  round: {round}                        # 检视轮次，从 1 开始
  commit_id: "{commit_id}"              # 完整 40 位 commit SHA
  change_id: "{change_id}"              # Change-Id（无则填 "no-change-id"）
  report_id: "{change_id}-R{round}"
  date: "{date}"                        # YYYY-MM-DD
  gate_decision: "{gate_decision}"      # approve | conditional | block | insufficient
  risk_level: "{risk_level}"            # low | medium | high | unknown
  score: {score}                        # 0-100 整数
  dimensions_required: [{dims}]         # Step 0 用户选定的维度标识列表
  dimensions_executed: [{dims}]         # 实际执行的维度标识列表
  findings_total: {n}
  findings_by_severity: {p0: {n}, p1: {n}, p2: {n}, p3: {n}}
  gate_blockers: [{finding_id}]         # 导致 block 的发现 ID 列表
  must_fix: {n}                         # P0/P1 总数
  followups: {n}                        # P2/P3 总数
```
<!-- codecheck-report-metadata:end -->

**维度标识取值域**（固定，不得自创）：
`functionality` | `logic` | `security` | `performance` | `compatibility` | `dfx` | `checklist` | `test` | `architecture`

**问题编号规则**（跨报告唯一，由维度前缀 + 三位序号组成）：

| 维度 | 前缀 | 示例 |
|---|---|---|
| 功能 | `FUNC` | FUNC-001 |
| 逻辑 | `LOGIC` | LOGIC-001 |
| 安全 | `SEC` | SEC-001 |
| 性能 | `PERF` | PERF-001 |
| 兼容性 | `COMP` | COMP-001 |
| DFX | `DFX` | DFX-001 |
| 规范 | `CHK` | CHK-001 |
| 测试 | `TEST` | TEST-001 |
| 架构 | `ARCH` | ARCH-001 |

**严重等级定义**（全维度统一归一化）：

| 等级 | 名称 | 判定标准 |
|---|---|---|
| P0 | 致命 | 内存安全漏洞、权限绕过、公共 API 破坏性变更、崩溃风险、数据丢失——必须修复，阻止上库 |
| P1 | 严重 | 输入校验缺失、并发缺陷、兼容性隐患、错误处理不完整——强烈建议修复 |
| P2 | 一般 | 规范违反、可优化的性能问题、DFX 覆盖不足——建议跟进 |
| P3 | 提示 | 风格建议、可选优化——按排期处理 |

---

## 部分维度检视标注（必写条件）

当 `dimensions_executed` ≠ 全部 9 个维度时，必须在 YAML 块之后、第 1 节之前插入以下标注块：

```
> ⚠️ **部分维度检视**：本次仅执行 {dimensions_executed} 维度。
> 未选维度（{列出未选维度中文名称}）不在本次结论保障范围内，
> `gate_decision` 仅对已检维度有效，不代表整体质量放行。
```

全量检视时本标注块省略。

---

## 报告正文（固定 6 章节，顺序不得调整）

### 标题行

```
# 代码检视报告 — {scope}（Round {round}）
```

---

## 1. 门禁结论

| 项目 | 结论 |
|---|---|
| 决策 | **{gate_decision}** |
| 风险等级 | {risk_emoji} {risk_level} |
| 评分 | **{score}/100** |
| 阻塞项 | {gate_blockers_summary 或 "无"} |
| 必须修复（P0/P1） | {must_fix_count} 项 |
| 建议跟进（P2/P3） | {followups_count} 项 |

**一句话结论**：{one_line_conclusion}

---

## 2. 扣分原因（仅 gate_decision=block 时呈现；其余决策时本节省略）

> 共扣 **{total_deduction}** 分，由 {p2_count} 个 P2 和 {p3_count} 个 P3 组成（P0/P1 直接决定决策，不进入扣分明细）。
>
> 无 P2/P3 发现时（如仅有 P0 触发 block）固定写法：**无扣分明细（无 P2/P3 发现，block 决策由 P0 直接判定，修复 P0 后重新评分）**，下方表格与"快速提分"段省略。

| 扣分项 | 扣分数 | 问题 | 位置 |
|---|---|---|---|
| {finding_id} | −{deduction} | {问题摘要} | `file:line` |

**如果想快速提分**：优先修复 **{top_deduction_id}（−{top_deduction_score} 分）**，再顺手补低优先级项即可。

---

## 3. 必须立即处理（P0/P1）

| ID | 优先级 | 维度 | 问题 | file:line | 触发路径 | 影响 |
|---|---|---|---|---|---|---|
| {finding_id} | P0 | security | {问题摘要} | `path:line` | {触发路径} | {影响} |

> 无 P0/P1 项时固定写法：**无。**　详情见第 6 节。

---

## 4. 建议本轮或下一补档处理（P2/P3）

| ID | 优先级 | 问题 | 建议行动 | 排期 |
|---|---|---|---|---|
| {finding_id} | P2 | {问题摘要} | {建议} | 本轮/下一补档 |

---

## 5. 分维度速览

| 维度 | 结果 | 关键说明 |
|---|---|---|
| 安全 (security) | pass / warn / fail / N/A | {一句话结论或 N/A 理由} |
| 功能 (functionality) | ... | ... |

> 结果取值：`pass`（无发现）/ `warn`（仅 P2/P3）/ `fail`（存在 P0/P1）/ `N/A`（该维度无适用面，
> 如纯文档变更时的安全维度；N/A 仍计入 dimensions_executed，不计为缺失）。

---

## 6. 关键发现详情

> P0/P1 必出全量卡片；P2/P3 按需精选或全出。每条发现按以下固定卡片格式呈现：

### [{finding_id}] {finding_title} ({severity}, dimension={dimension})

- **位置**：`{file}:{line}`
- **触发路径**：{trigger_path}
- **影响**：{impact}
- **证据**：{代码片段或检测命令输出}
- **规范依据**：{官方规则编号 / ANS 陷阱编号，如 "规则3.1.1"、"A2 Parcelable 兼容"}
- **建议**：{recommendation，含修复示例代码（可选）}

---

## 评分与门禁决策矩阵（权威规则，生成时执行，不在报告正文重复呈现）

1. **评分公式**：`score = max(0, 100 − (30×P0 + 12×P1 + 5×P2 + 2×P3))`，其中 P0/P1/P2/P3 为 refute 过滤后的最终发现数量。
2. **决策矩阵**（按顺序判定，命中即停）：
   1. `dimensions_required` 中任一选定维度未执行 → `insufficient`
   2. 存在 P0 → `block`
   3. 存在 P1 → `conditional`
   4. score ≥ 90 → `approve`
   5. score ≥ 70 → `conditional`
   6. 否则 → `block`
3. **风险等级**：`high`（有 P0 或 score<70）/ `medium`（有 P1 或 score≥70）/ `low`（score≥90 且无 P0/P1）/ `unknown`（insufficient）。
4. **一致性要求**：YAML 元数据块与第 1 节表格中的 `score` / `gate_decision` / `risk_level` **必须完全一致**。
5. **跨维度去重**：以 `file:line` 为第一键；同位置多维度命中合并为一条，标注全部维度来源（问题 ID 保留主维度 ID，其余 ID 以"关联"列出）。同根因不同位置的合并由 Step 5 refute 完成。

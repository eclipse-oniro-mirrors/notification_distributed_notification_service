---
name: build
description: 编译构建验证 skill。支持双模式运行：Workflow 模式（feature-agent 调用）和 Ad-hoc 模式（人工/其他场景）。自包含，不依赖其他 skill。
---
# Build Skill — 编译构建验证

## 角色定义

你是 **Build Skill**，专门负责编译构建验证。本 skill 自包含，不依赖其他 skill，支持两种调用模式：

- **Workflow 模式**：由 feature-agent 在任务 Review 通过后调用，执行统一编译验证
- **Ad-hoc 模式**：由人工或其他场景直接调用，执行编译并诊断结果

**核心原则**：

- 你只做编译验证，不做代码检视
- 你不修改业务代码，只执行编译并报告结果
- 编译失败时，你提供精确的诊断信息（含出错文件路径）
- 你信任本 skill 的诊断脚本，不凭终端输出猜测错误原因

`<skill-dir>` 指本 SKILL.md 所在目录。

---

## 运行模式检测

根据输入参数自动检测运行模式：

| 条件 | 模式 | 说明 |
|------|------|------|
| 输入包含 `task_ids`（非空数组） | **Workflow 模式** | feature-agent 调用 |
| 输入不包含 `task_ids` 或为空 | **Ad-hoc 模式** | 人工或其他场景 |

---

## 输入

### Workflow 模式输入

从 feature-agent 接收：
- `task_ids`：本次编译验证涉及的任务 ID 列表（所有已通过 Review 的任务）
- `kb_dir`：工作目录（由调用方指定）
- `files_changed`: [<所有任务修改文件的并集>]
- `test_commands`: [<编译/测试命令并集>]（来自 plan.md 中各任务的 test_commands 合并去重）

### Ad-hoc 模式输入

从用户或其他场景接收（均为可选）：
- `build_command`：用户直接指定的完整编译命令
- `build_target`：用户指定的编译目标名（如 `distributed_notification_service`）
- `product`：产品名，默认 `rk3568`
- `files_changed`：变更文件列表（可选，若未提供则从 `git diff` 推导）

**Ad-hoc 模式默认行为**：若所有参数均未提供，自动从 `git diff --name-only HEAD~1` 获取变更文件，走文件推导逻辑确定编译目标。

---

## 编译基础知识

### 编译命令结构

```bash
./build.sh --export-para PYCACHE_ENABLE:true --product-name <product> --build-target <target> --ccache [--fast-rebuild]
```

### 编译日志路径

| 产品类型 | 主编译日志路径 |
|---------|-------------|
| 常规产品（如 rk3568） | `out/<product>/build.log` |
| SDK（ohos-sdk） | `out/sdk/build.log` |
| Host（host_product） | `out/host/host_product/build.log` |
| 独立编译（hb build） | `out/standard/build.log` |
| 后台编译 | `out/build_background.log` |

### 快速重建规则

**可使用 `--fast-rebuild`**：仅源代码变更（.cpp, .h, .ts, .ets）

**禁止使用 `--fast-rebuild`**：
- BUILD.gn 或 *.gni 文件被修改
- 首次编译或 out/ 目录被清理后
- 新增依赖

### 编译成功标识

- 退出码 `0`
- 日志包含 `=====build successful=====`

---

## 执行流程

### Step 1: 定位 OpenHarmony 根目录

定位 OpenHarmony 根目录（包含 `.gn` 和 `build.sh` 的目录）：

```bash
find_oh_root() {
    local dir="${1:-$PWD}"
    while [[ "$dir" != "/" ]]; do
        if [[ -f "$dir/.gn" && -f "$dir/build.sh" ]]; then
            echo "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done
    return 1
}
OH_ROOT=$(find_oh_root "$PWD")
```

若根目录不存在，立即报告 BUILD_FAIL 并停止。

### Step 2: 确定编译命令

#### Workflow 模式

按以下流程确定编译命令。核心原则：**test_commands 显式指定优先，文件变更推导兜底**。

##### 2.1 收集 test_commands

从所有任务的 `test_commands` 中收集编译目标：

1. 合并所有任务的 `test_commands` 并去重
2. 过滤掉空值（文档类任务的 `test_commands` 通常为空数组 `[]`）
3. 若合并后非空，进入 **2.2**；否则进入 **2.3**

##### 2.2 使用 test_commands 构建编译命令

**多 target 合并**：若 test_commands 包含多个目标，合并为一条命令的多个 `--build-target` 参数：

```bash
./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 \
    --build-target target_a \
    --build-target target_b \
    --build-target target_c \
    --ccache
```

**GN label 识别**：若 test_commands 中包含 GN label（格式 `path:target`），直接作为 `--build-target` 参数值使用。

##### 2.3 根据文件变更推导编译目标（test_commands 为空时）

按以下优先级推导：

**优先级 1：自动推导 GN label**

若 `files_changed` 集中在某个含 BUILD.gn 的子目录：

1. 从修改文件的**相对路径**（相对于仓库根目录）向上查找最近的 BUILD.gn
2. 读取 BUILD.gn 中的 target 名称
3. 计算 BUILD.gn 所在目录相对于 OH 根目录的路径，构造 GN label：`<oh_root_relative_path>:<target_name>`

推导示例：
```
files_changed: ["services/ans/src/ans_service.cpp"]  (相对于仓库根目录)
→ 向上查找 BUILD.gn: services/ans/BUILD.gn  (相对路径)
→ 读取 target: ohos_shared_library("ans_service")
→ 仓库在 OH 根目录下的路径: base/notification/distributed_notification_service
→ 构造 GN label: base/notification/distributed_notification_service/services/ans:ans_service
```

**优先级 2：根据文件路径模式推断**

| files_changed 匹配模式 | 编译目标 | 说明 |
|---|---|---|
| `test/fuzztest/**` | `distributed_notification_service_fuzz_test` | 模糊测试 |
| `*/test/unittest/**` 或 `*/test/moduletest/**` | `distributed_notification_service_unit_test` | 单元测试/模块测试 |
| 同时包含单元测试和模糊测试 | 合并两个 target（多 `--build-target`） | 同时编译 |
| 仅源代码文件（非 test 目录） | `distributed_notification_service` | 部件编译 |
| 仅文档文件（`.md`、`.txt`） | 跳过编译，直接 BUILD_PASS | 无需编译验证 |

命令示例：
```bash
# 单元测试
./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 --build-target distributed_notification_service_unit_test --ccache

# 模糊测试
./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 --build-target distributed_notification_service_fuzz_test --ccache

# 同时包含单元测试和模糊测试
./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 \
    --build-target distributed_notification_service_unit_test \
    --build-target distributed_notification_service_fuzz_test \
    --ccache

# 部件编译
./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 --build-target distributed_notification_service --ccache
```

**文档类任务快速通道**：若所有 `files_changed` 均为文档文件（`.md`、`.txt`、`.json` 等非编译文件），跳过编译步骤，直接输出 BUILD_PASS。

##### 2.4 GN 文件变更检测

若 `files_changed` 包含 BUILD.gn 或 *.gni 文件，标记 `gn_changed: true`

#### Ad-hoc 模式

按以下优先级确定编译命令：

**优先级 1：用户指定 build_command**

若用户提供了完整的 `build_command`，直接使用。

**优先级 2：用户指定 build_target**

若用户提供了 `build_target`，构造命令：
```bash
./build.sh --export-para PYCACHE_ENABLE:true --product-name <product> --build-target <build_target> --ccache
```

**优先级 3：从 git diff 推导**

若用户未提供任何参数，自动获取变更文件：
```bash
cd "$OH_ROOT"
git diff --name-only HEAD~1
```

然后复用 Workflow 模式的 **2.3 文件推导逻辑**（优先级 1 和 2）确定编译目标。

**优先级 4：兜底**

若 git diff 无变更或推导失败，使用默认目标：
```bash
./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 --build-target distributed_notification_service --ccache
```

### Step 3: 检查快速重建条件

使用本 skill 的脚本判断是否可使用 `--fast-rebuild`：

```bash
bash <skill-dir>/scripts/check_fast_rebuild.sh 30 "$OH_ROOT"
```

**禁止使用 `--fast-rebuild` 的情况**：
- BUILD.gn 或 *.gni 文件在本次变更中被修改
- 脚本返回不建议使用快速重建

### Step 4: 执行编译（后台模式）

使用后台编译避免阻塞超时，通过进度感知轮询监控编译状态。

#### 4.1 启动后台编译

```bash
bash <skill-dir>/scripts/start_background_build.sh "<编译命令>" "$OH_ROOT"
```

脚本会：
- 用 `nohup` 后台启动编译进程
- 输出重定向到 `$OH_ROOT/out/build_background.log`
- 记录 PID 到 `$OH_ROOT/.build.pid`

#### 4.2 轮询编译进度

```bash
bash <skill-dir>/scripts/poll_build.sh <product> "$OH_ROOT" [max_wait_seconds]
```

轮询特性：
- **进度感知**：解析 ninja 输出 `[current/total]` 获取编译进度
- **自适应延迟**：编译初期延迟 300s（5min），随进度递减至 10s
- **默认超时**：7200s（120 分钟）

退出码：
- `0`：编译成功
- `1`：编译失败
- `2`：编译超时
- `3`：进程未找到

#### 4.3 记录编译信息

记录：
- 编译命令（完整命令）
- 编译模式：`background`
- 退出码（从 poll_build.sh 获取）
- 编译耗时（从 poll_build.sh 输出解析）
- 是否使用了 `--fast-rebuild`

### Step 5: 判定编译结果

根据 `poll_build.sh` 的退出码判定：

| poll_build.sh 退出码 | 判定结果 | 后续动作 |
|---------------------|---------|---------|
| `0` | BUILD_PASS | 进入 Step 7 输出成功结果 |
| `1` | BUILD_FAIL | 进入 Step 6 诊断 |
| `2` | BUILD_TIMEOUT | 报告超时，建议增加超时时间或检查编译是否卡住 |
| `3` | BUILD_FAIL | 进程异常退出，检查日志诊断 |

**编译成功判定**（全部满足）：
- poll_build.sh 退出码为 `0`
- 后台编译日志包含 `=====build successful=====` 或等效成功标识
- 主编译日志中无最终 fatal/error 段

**编译成功时**，进入 Step 7 输出结果。

### Step 6: 编译失败诊断

编译失败时，**必须从主编译日志诊断**，不得仅从终端输出尾部猜测原因。

1. **定位主编译日志**：
   - 后台编译日志：`out/build_background.log`（优先检查）
   - 常规产品：`out/<product>/build.log`
   - 独立编译：`out/standard/build.log`

2. **使用诊断脚本**：
   ```bash
   bash <skill-dir>/scripts/find_recent_errors.sh <product> "$OH_ROOT"
   bash <skill-dir>/scripts/analyze_build_error.sh <product> "$OH_ROOT"
   ```

3. **提取诊断信息**：
   - 首个失败错误的完整信息
   - 错误类型（编译错误 / 链接错误 / 依赖缺失 / 配置错误）
   - 出错文件路径和行号
   - 错误上下文（前后若干行）

4. **分类错误**：

   | 错误类型 | 说明 | 建议修复方向 | 可重试 |
   |----------|------|------------|--------|
   | COMPILE_ERROR | 语法错误、类型不匹配、未声明标识符 | 修复源代码 | 是 |
   | LINK_ERROR | 未定义符号、重复定义 | 检查依赖和链接配置 | 是 |
   | DEPENDENCY_MISSING | 头文件找不到、模块不存在 | 检查 BUILD.gn 依赖声明 | 是 |
   | GN_CONFIG_ERROR | GN 配置错误、目标未定义 | 检查 BUILD.gn 和 .gni 文件 | **否**（直接 human_review） |

5. **若为链接错误或依赖缺失**，检查 BUILD.gn 中的 `deps` 和 `external_deps` 是否正确声明。

6. **关联任务定位**（仅 Workflow 模式）：

   根据出错文件路径（`error_file`），按以下策略匹配关联任务：

   **策略 A：直接匹配**
   将 `error_file` 与各任务的 `files_write` 列表匹配，找到直接修改该文件的任务。

   **策略 B：头文件依赖匹配**（策略 A 无匹配时）
   若 `error_file` 不在任何任务的 `files_write` 中，检查错误上下文中的 `#include` 路径：
   - 从错误上下文中提取被引用的头文件路径
   - 将头文件路径与各任务的 `files_write` 匹配
   - 若匹配到，该任务可能是根因（修改了头文件导致其他文件编译失败）

   **策略 C：目录归属匹配**（策略 A、B 均无匹配时）
   将 `error_file` 所在目录与各任务的 `files_write` 目录匹配，找到修改了同目录文件的任务。

   **输出**：`affected_task_ids` 包含所有匹配到的任务 ID。若多个任务匹配，全部列出，由调用方决定修复范围。

### Step 7: 输出结果

#### Workflow 模式输出

##### 编译成功输出

```text
BUILD_PASS
task_ids: [<task_id_1>, <task_id_2>, ...]
build_command: <完整编译命令>
build_mode: background
fast_rebuild: <true/false>
build_time: <耗时>
exit_code: 0

编译验证通过:
- 编译目标: <target>
- 编译产品: <product>
- 涉及任务数: <N>
- 修改文件数: <M>
- GN 文件变更: <true/false>

编译日志: out/build_background.log (后台) / out/<product>/build.log (主日志)
```

##### 编译失败输出

```text
BUILD_FAIL
task_ids: [<task_id_1>, <task_id_2>, ...]
build_command: <完整编译命令>
build_mode: background
fast_rebuild: <true/false>
build_time: <耗时>
exit_code: <非零退出码>

编译失败诊断:
- 错误类型: <COMPILE_ERROR/LINK_ERROR/DEPENDENCY_MISSING/GN_CONFIG_ERROR>
- 可重试: <true/false> (GN_CONFIG_ERROR 为 false，其余为 true)
- 首个错误位置: <文件路径>:<行号>
- 关联任务: <根据出错文件路径匹配的 task_id>
- 错误信息: <完整错误信息>
- 错误上下文:
  <错误前后若干行>

修复建议:
1. <具体修复建议1>
2. <具体修复建议2>

编译日志: out/build_background.log (后台) / out/<product>/build.log (主日志)
详细诊断: 见 build-log.md
```

#### Ad-hoc 模式输出

##### 编译成功输出

```text
BUILD_PASS
build_command: <完整编译命令>
build_time: <耗时>
exit_code: 0

编译成功:
- 编译目标: <target>
- 编译产品: <product>

编译日志: out/build_background.log (后台) / out/<product>/build.log (主日志)
```

##### 编译失败输出

```text
BUILD_FAIL
build_command: <完整编译命令>
build_time: <耗时>
exit_code: <非零退出码>

编译失败诊断:
- 错误类型: <COMPILE_ERROR/LINK_ERROR/DEPENDENCY_MISSING/GN_CONFIG_ERROR>
- 首个错误位置: <文件路径>:<行号>
- 错误信息: <完整错误信息>
- 错误上下文:
  <错误前后若干行>

修复建议:
1. <具体修复建议1>
2. <具体修复建议2>

编译日志: out/build_background.log (后台) / out/<product>/build.log (主日志)
```

---

## 编译日志记录

### Workflow 模式

无论通过还是失败，将编译验证记录追加写入 `{kb_dir}/build-log.md`，记录本次统一编译涉及的所有任务和结果，详见 @references/build-templates.md 中的 "编译日志记录模板"。

### Ad-hoc 模式

不写入 build-log.md。编译结果仅通过标准输出返回给调用方。

---

## 完成后汇报

### Workflow 模式

向 feature-agent 汇报统一编译验证结果：

#### 编译成功时

```json
{
  "task_ids": ["<task_id_1>", "<task_id_2>"],
  "build_status": "pass",
  "build_command": "<完整编译命令>",
  "build_mode": "background",
  "fast_rebuild": false,
  "build_time": "<耗时>",
  "exit_code": 0,
  "build_log": "out/build_background.log",
  "primary_log": "out/<product>/build.log"
}
```

#### 编译失败时

```json
{
  "task_ids": ["<task_id_1>", "<task_id_2>"],
  "build_status": "fail",
  "build_command": "<完整编译命令>",
  "build_mode": "background",
  "exit_code": 1,
  "error_type": "<COMPILE_ERROR/LINK_ERROR/DEPENDENCY_MISSING/GN_CONFIG_ERROR>",
  "retryable": true,
  "first_error": "<首个错误信息>",
  "error_file": "<出错文件路径>",
  "error_line": "<出错行号>",
  "affected_task_ids": ["<根据出错文件匹配的 task_id>"],
  "fix_suggestions": ["<修复建议1>", "<修复建议2>"],
  "build_log": "out/build_background.log",
  "primary_log": "out/<product>/build.log"
}
```

**retryable 字段说明**：
- `COMPILE_ERROR` / `LINK_ERROR` / `DEPENDENCY_MISSING` → `retryable: true`
- `GN_CONFIG_ERROR` → `retryable: false`（调用方将直接标记 human_review，不消耗重试次数）

**affected_task_ids 字段说明**：
- 按 Step 6 的三级匹配策略（直接匹配 → 头文件依赖匹配 → 目录归属匹配）确定出错文件关联的任务
- 调用方据此决定哪些任务需要重试修复

### Ad-hoc 模式

向用户或调用方汇报编译结果（简洁文本格式）：

#### 编译成功时

```text
编译成功
命令: <完整编译命令>
耗时: <耗时>
日志: out/<product>/build.log
```

#### 编译失败时

```text
编译失败
命令: <完整编译命令>
耗时: <耗时>

错误类型: <COMPILE_ERROR/LINK_ERROR/DEPENDENCY_MISSING/GN_CONFIG_ERROR>
错误位置: <文件路径>:<行号>
错误信息: <首个错误信息>

修复建议:
1. <具体修复建议1>
2. <具体修复建议2>

日志: out/<product>/build.log
```

---

## Build 重试诊断信息（仅 Workflow 模式，供 Execute 子代理消费）

编译失败且 `retryable: true` 时，调用方将以下诊断信息传递给 Execute 子代理，用于指导修复：

```json
{
  "build_retry_info": {
    "error_type": "<COMPILE_ERROR/LINK_ERROR/DEPENDENCY_MISSING>",
    "error_file": "<出错文件路径>",
    "error_line": "<出错行号>",
    "first_error": "<首个错误的完整信息>",
    "error_context": "<错误前后若干行代码>",
    "fix_suggestions": ["<修复建议1>", "<修复建议2>"]
  }
}
```

Execute 子代理在 Step 1e（读取重试信息）中消费此诊断信息，仅修复编译问题，不改变实现逻辑。

---

## 重要约束

1. **不修改业务代码**：你只执行编译和诊断，不修改任何业务源代码文件（build-log.md 除外）
2. **不猜测错误原因**：必须从主编译日志提取错误信息，使用本 skill 提供的诊断脚本
3. **不执行 repo sync 或环境初始化**：除非调用方明确要求
4. **不删除 out/ 目录**：除非调用方明确要求清理
5. **优先定向编译**：使用 `--build-target` 进行定向编译，避免全量编译
6. **记录编译日志路径**：始终在输出中包含编译日志路径，便于后续查阅

---

## Bundled Resources

### 脚本

| 脚本 | 用途 |
|------|------|
| `scripts/start_background_build.sh` | 后台启动编译进程，记录 PID |
| `scripts/poll_build.sh` | 进度感知轮询编译状态（自适应延迟 10s-300s） |
| `scripts/check_fast_rebuild.sh` | 判断是否可使用 `--fast-rebuild` |
| `scripts/find_recent_errors.sh` | 快速扫描编译日志中的近期错误 |
| `scripts/analyze_build_error.sh` | 从主编译日志提取并汇总错误信息 |

### 参考文档

| 文档 | 用途 |
|------|------|
| `references/build-templates.md` | 编译输出模板、日志记录模板、命令选择规则 |

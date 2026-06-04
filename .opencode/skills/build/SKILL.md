---
name: build
description: 编译构建验证 skill。在所有任务通过代码检视后执行统一编译验证，确保所有代码变更可通过编译，并提供详细的编译失败诊断。与工作流无关，由调用方传入工作目录和上下文。
---
# Build Skill — 编译构建验证

## 角色定义

你是 **Build Skill**，专门负责编译构建验证。你在**所有任务**通过 Review Skill 代码检视后由调用方调用，使用 **openharmony-build skill** 执行统一编译验证，确保所有代码变更可通过编译。本 skill 与工作流无关，由调用方传入工作目录和上下文。

**核心原则**：

- 你只做编译验证，不做代码检视（那是 Review Skill 的职责）
- 你不修改业务代码，只执行编译并报告结果
- 你对所有任务的变更文件进行**一次性统一编译**，而非逐任务编译
- 编译失败时，你提供精确的诊断信息（含出错文件路径），帮助调用方定位关联任务并安排修复
- 你信任 openharmony-build skill 的诊断脚本，不凭终端输出猜测错误原因

---

## 输入

从调用方接收：
- `task_ids`：本次编译验证涉及的任务 ID 列表（所有已通过 Review 的任务）
- `kb_dir`：工作目录（由调用方指定）
- `files_changed`: [<所有任务修改文件的并集>]
- `test_commands`: [<编译/测试命令并集>]（来自 plan.md 中各任务的 test_commands 合并去重）

**编译构建使用的 Skill**：
- Skill 名称：`openharmony-build`
- 使用前先加载：`skill(name="openharmony-build")`
- Skill 目录：`.opencode/skills/openharmony-build/`

---

## 执行流程

### Step 1: 加载 Skill 并定位 OpenHarmony 根目录

1. 加载 openharmony-build skill：
   ```text
   skill(name="openharmony-build")
   ```

2. 定位 OpenHarmony 根目录（包含 `.gn` 和 `build.sh` 的目录）：
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

3. 若根目录不存在，立即报告 BUILD_FAIL 并停止。

### Step 2: 确定编译命令

按优先级选择编译命令：

1. **优先使用 `test_commands`**：合并所有任务的 test_commands 并去重，直接使用
2. **根据文件变更推断目标**（当 test_commands 为空时）：
   - 若 `files_changed`（所有任务修改文件的并集）包含 `test/` 目录下的文件，使用测试编译：
     ```bash
     ./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 --build-target distributed_notification_service_test --ccache
     ```
   - 否则使用部件编译：
     ```bash
     ./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 --build-target distributed_notification_service --ccache
     ```
3. **若 `files_changed` 包含 BUILD.gn 或 *.gni 文件**，标记 `gn_changed: true`

### Step 3: 检查快速重建条件

使用 openharmony-build skill 的脚本判断是否可使用 `--fast-rebuild`：

```bash
bash <skill-dir>/scripts/check_fast_rebuild.sh 30 "$OH_ROOT"
```

**禁止使用 `--fast-rebuild` 的情况**：
- BUILD.gn 或 *.gni 文件在本次变更中被修改
- 脚本返回不建议使用快速重建

### Step 4: 执行编译

从 OpenHarmony 根目录执行编译命令：

```bash
cd "$OH_ROOT" && <编译命令>
```

记录：
- 编译命令（完整命令）
- 退出码
- 编译耗时
- 是否使用了 `--fast-rebuild`

### Step 5: 判定编译结果

**编译成功判定**（全部满足）：
- 命令退出码为 `0`
- 输出包含 `=====build successful=====` 或等效成功标识
- 主编译日志中无最终 fatal/error 段

**编译成功时**，进入 Step 7 输出结果。

### Step 6: 编译失败诊断

编译失败时，**必须从主编译日志诊断**，不得仅从终端输出尾部猜测原因。

1. **定位主编译日志**：
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

6. **关联任务定位**：根据出错文件路径（`error_file`），匹配各任务的 `files_write` 列表，确定哪些任务需要修复。调用方据此决定重试范围。

### Step 7: 输出结果

#### 编译成功输出

```text
BUILD_PASS
task_ids: [<task_id_1>, <task_id_2>, ...]
build_command: <完整编译命令>
fast_rebuild: <true/false>
build_time: <耗时>
exit_code: 0

编译验证通过:
- 编译目标: <target>
- 编译产品: <product>
- 涉及任务数: <N>
- 修改文件数: <M>
- GN 文件变更: <true/false>

编译日志: out/<product>/build.log
```

#### 编译失败输出

```text
BUILD_FAIL
task_ids: [<task_id_1>, <task_id_2>, ...]
build_command: <完整编译命令>
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

编译日志: out/<product>/build.log
详细诊断: 见 build-log.md
```

---

## 编译日志记录

无论通过还是失败，将编译验证记录追加写入 `{kb_dir}/build-log.md`，记录本次统一编译涉及的所有任务和结果，详见 @references/build-templates.md 中的 "编译日志记录模板"。

---

## 完成后汇报

向调用方汇报统一编译验证结果：

### 编译成功时

```json
{
  "task_ids": ["<task_id_1>", "<task_id_2>"],
  "build_status": "pass",
  "build_command": "<完整编译命令>",
  "fast_rebuild": false,
  "build_time": "<耗时>",
  "exit_code": 0,
  "build_log": "out/<product>/build.log"
}
```

### 编译失败时

```json
{
  "task_ids": ["<task_id_1>", "<task_id_2>"],
  "build_status": "fail",
  "build_command": "<完整编译命令>",
  "exit_code": 1,
  "error_type": "<COMPILE_ERROR/LINK_ERROR/DEPENDENCY_MISSING/GN_CONFIG_ERROR>",
  "retryable": true,
  "first_error": "<首个错误信息>",
  "error_file": "<出错文件路径>",
  "error_line": "<出错行号>",
  "affected_task_ids": ["<根据出错文件匹配的 task_id>"],
  "fix_suggestions": ["<修复建议1>", "<修复建议2>"],
  "build_log": "out/<product>/build.log"
}
```

**retryable 字段说明**：
- `COMPILE_ERROR` / `LINK_ERROR` / `DEPENDENCY_MISSING` → `retryable: true`
- `GN_CONFIG_ERROR` → `retryable: false`（调用方将直接标记 human_review，不消耗重试次数）

**affected_task_ids 字段说明**：
- 根据 `error_file` 匹配各任务的 `files_write` 列表，确定出错文件关联的任务
- 调用方据此决定哪些任务需要重试修复

---

## 重要约束

1. **不修改业务代码**：你只执行编译和诊断，不修改任何业务源代码文件（build-log.md 除外）
2. **不猜测错误原因**：必须从主编译日志提取错误信息，使用 skill 提供的诊断脚本
3. **不执行 repo sync 或环境初始化**：除非调用方明确要求
4. **不删除 out/ 目录**：除非调用方明确要求清理
5. **优先定向编译**：使用 `--build-target` 进行定向编译，避免全量编译
6. **记录编译日志路径**：始终在输出中包含编译日志路径，便于后续查阅

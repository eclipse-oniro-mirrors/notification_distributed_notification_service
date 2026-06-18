# 编译构建验证模板

本文件包含 Build Skill 使用的编译验证相关模板。

**重要约定**：
- **Workflow 模式**：所有过程文档存放在 `{kb_dir}/` 目录下，该目录由调用方指定
- **Ad-hoc 模式**：不写入 build-log.md，仅通过标准输出返回结果

---

## 1. Workflow 模式 - 编译成功输出模板

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

---

## 2. Workflow 模式 - 编译失败输出模板

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
  <错误前后若干行代码>

修复建议:
1. <具体修复建议1>
2. <具体修复建议2>
3. <具体修复建议3>

编译日志: out/build_background.log (后台) / out/<product>/build.log (主日志)
详细诊断: {kb_dir}/build-log.md
```

---

## 3. Workflow 模式 - 编译日志记录模板

每次编译验证追加写入 `{kb_dir}/build-log.md`：

```text
## 编译验证记录 - <timestamp>

### 任务信息
- 任务ID: <task_id>
- 修改文件数: <N>
- 修改文件列表:
  - <file1>
  - <file2>

### 编译配置
- 编译命令: <完整编译命令>
- 编译模式: background
- 编译目标: <target>
- 编译产品: <product>
- 快速重建: <true/false>
- GN 文件变更: <true/false>

### 编译结果
- 退出码: <exit_code>
- 编译耗时: <时间>
- 结果: <成功/失败>

### 编译日志路径
- 后台编译日志: out/build_background.log
- 主编译日志: out/<product>/build.log

### 失败诊断（仅失败时记录）
- 错误类型: <COMPILE_ERROR/LINK_ERROR/DEPENDENCY_MISSING/GN_CONFIG_ERROR>
- 首个错误位置: <文件路径>:<行号>
- 错误信息: <完整错误信息>
- 错误上下文:
  ```
  <错误前后若干行代码>
  ```
- 诊断脚本输出:
  ```
  <find_recent_errors.sh 输出>
  <analyze_build_error.sh 输出>
  ```

### 修复建议
1. <具体修复建议1>
2. <具体修复建议2>
```

---

## 4. 编译命令选择规则

### 4.1 命令选择优先级

| 优先级 | 场景 | 编译命令 |
|--------|------|---------|
| 0 | 所有 files_changed 均为文档文件（`.md`/`.txt`/`.json`） | 跳过编译，直接 BUILD_PASS |
| 1 | test_commands 非空 | 合并去重后使用：`--build-target A --build-target B` |
| 2 | files_changed 可推导 GN label | 推导并使用：`--build-target path:target` |
| 3 | files_changed 包含 `test/fuzztest/**` | `--build-target distributed_notification_service_fuzz_test` |
| 4 | files_changed 包含 `*/test/unittest/**` 或 `*/test/moduletest/**` | `--build-target distributed_notification_service_unit_test` |
| 5 | 同时包含单元测试和模糊测试 | `--build-target distributed_notification_service_unit_test --build-target distributed_notification_service_fuzz_test` |
| 6 | 仅修改源代码（非 test 目录） | `--build-target distributed_notification_service` |
| - | 修改了 BUILD.gn 或 *.gni | 禁止使用 `--fast-rebuild` |

### 4.2 多 Target 合并

当 test_commands 包含多个目标时，合并为一条命令：

```bash
./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 \
    --build-target target_a \
    --build-target target_b \
    --build-target target_c \
    --ccache
```

### 4.3 GN Label 推导规则

当 files_changed 集中在某个含 BUILD.gn 的子目录时：

1. 从修改文件的**相对路径**（相对于仓库根目录）向上查找最近的 BUILD.gn
2. 读取 BUILD.gn 中的 target 名称
3. 计算 BUILD.gn 所在目录相对于 OH 根目录的路径，构造 GN label：`<oh_root_relative_path>:<target_name>`

示例：
```
files_changed: ["services/ans/src/ans_service.cpp"]  (相对于仓库根目录)
→ 向上查找 BUILD.gn: services/ans/BUILD.gn  (相对路径)
→ target: ohos_shared_library("ans_service")
→ 仓库在 OH 根目录下的路径: base/notification/distributed_notification_service
→ GN label: base/notification/distributed_notification_service/services/ans:ans_service
```

### 4.4 编译模式

所有编译均使用**后台模式**：

```bash
# 启动后台编译
bash <skill-dir>/scripts/start_background_build.sh "<编译命令>" "$OH_ROOT"

# 轮询等待完成
bash <skill-dir>/scripts/poll_build.sh <product> "$OH_ROOT" [max_wait_seconds]
```

---

## 5. 错误类型分类表

| 错误类型 | 典型特征 | 建议修复方向 | 可重试 |
|----------|---------|------------|--------|
| COMPILE_ERROR | syntax error, undeclared identifier, type mismatch | 修复源代码语法或类型问题 | 是 |
| LINK_ERROR | undefined reference, multiple definition | 检查 BUILD.gn 的 deps 和链接配置 | 是 |
| DEPENDENCY_MISSING | fatal error: xxx.h: No such file | 补充 BUILD.gn 中的 deps/external_deps | 是 |
| GN_CONFIG_ERROR | GN target not found, invalid config | 修复 BUILD.gn 或 .gni 配置 | **否**（直接 human_review） |

**可重试规则**：
- 可重试错误：调用方将诊断信息传递给 Execute Skill，走 Execute → Review → Build 重试闭环
- 不可重试错误：调用方直接标记任务为 `human_review`，不消耗重试次数，等待用户决策

---

## 6. Build 重试诊断信息模板

编译失败且 `retryable: true` 时，调用方将以下诊断信息传递给 Execute 子代理：

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

## 7. Ad-hoc 模式 - 编译成功输出模板

```text
编译成功
命令: <完整编译命令>
耗时: <耗时>
日志: out/<product>/build.log
```

---

## 8. Ad-hoc 模式 - 编译失败输出模板

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

## 9. Ad-hoc 模式 - 命令确定规则

当用户未提供 `build_command` 或 `build_target` 时，从 `git diff` 推导：

```bash
cd "$OH_ROOT"
git diff --name-only HEAD~1
```

然后复用 Workflow 模式的文件推导逻辑（优先级 1 和 2）确定编译目标。

**兜底**：若 git diff 无变更或推导失败，使用默认目标：
```bash
./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 --build-target distributed_notification_service --ccache
```

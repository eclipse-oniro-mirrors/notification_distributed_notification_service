# 编译构建验证模板

本文件包含 Build Skill 使用的编译验证相关模板。

**重要约定**：所有过程文档存放在 `{kb_dir}/` 目录下，该目录由调用方指定。

---

## 1. 编译成功输出模板

```text
BUILD_PASS
task_id: <task_id>
build_command: <完整编译命令>
fast_rebuild: <true/false>
build_time: <耗时>
exit_code: 0

编译验证通过:
- 编译目标: <target>
- 编译产品: <product>
- 修改文件数: <N>
- GN 文件变更: <true/false>

编译日志: out/<product>/build.log
```

---

## 2. 编译失败输出模板

```text
BUILD_FAIL
task_id: <task_id>
build_command: <完整编译命令>
fast_rebuild: <true/false>
build_time: <耗时>
exit_code: <非零退出码>

编译失败诊断:
- 错误类型: <COMPILE_ERROR/LINK_ERROR/DEPENDENCY_MISSING/GN_CONFIG_ERROR>
- 首个错误位置: <文件路径>:<行号>
- 错误信息: <完整错误信息>
- 错误上下文:
  <错误前后若干行代码>

修复建议:
1. <具体修复建议1>
2. <具体修复建议2>
3. <具体修复建议3>

编译日志: out/<product>/build.log
详细诊断: {kb_dir}/build-log.md
```

---

## 3. 编译日志记录模板

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
- 编译目标: <target>
- 编译产品: <product>
- 快速重建: <true/false>
- GN 文件变更: <true/false>

### 编译结果
- 退出码: <exit_code>
- 编译耗时: <时间>
- 结果: <成功/失败>

### 编译日志路径
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

| 场景 | 编译命令 |
|------|---------|
| 任务声明了 test_commands | 使用 test_commands 中的命令 |
| files_changed 包含 test/ 文件 | `./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 --build-target distributed_notification_service_test --ccache` |
| 仅修改源代码 | `./build.sh --export-para PYCACHE_ENABLE:true --product-name rk3568 --build-target distributed_notification_service --ccache` |
| 修改了 BUILD.gn 或 *.gni | 禁止使用 `--fast-rebuild`，使用完整编译 |

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

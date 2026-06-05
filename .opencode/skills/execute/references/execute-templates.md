# 执行模板

本文件包含 Execute Skill 使用的执行阶段模板。

**重要约定**：所有过程文档存放在 `{kb_dir}/` 目录下，该目录由调用方指定。

## 1. 执行前确认模板

```text
[EXECUTE-CONFIRM] 准备执行任务:
- 任务ID: <task_id>
- 任务类型: <task_type>
- 可写文件: <files_write列表>
- 只读文件: <files_read列表>
- 验收标准: <acceptance_criteria列表>

是否继续执行?[继续/停止]
```

---

## 2. 任务阻塞输出模板

```text
[EXECUTE-BLOCKED] 任务执行被阻塞:
- 原因: <原因说明>
- 任务ID: <task_id>
- 问题: <具体问题>

请等待调用方决策。
```

---

## 3. 任务失败达到最大重试次数模板

```text
[EXECUTE-FAILED] 任务执行失败,已达到最大重试次数:
- 任务ID: <task_id>
- 重试次数: 3
- 最后失败原因: <原因>

需要人工介入处理。
```

---

## 4. 任务完成后输出模板

```text
[EXECUTE-COMPLETE] 任务执行完成:
- 任务ID: <task_id>
- 任务名称: <task_name>
- 任务类型: <task_type>
- 实际修改文件: <files_changed列表>
- 已移交 Review Skill 检视

任务总结文档: {kb_dir}/<task-name>.md

**执行摘要**:
- 新增代码行数: <N>
- 修改代码行数: <M>
- 新增文件数: <N>
- 修改文件数: <M>
- 新增测试用例: <N>

**关键实现**:
- <简要说明关键实现点1>
- <简要说明关键实现点2>
```

---

## 5. 任务失败输出模板

```text
[EXECUTE-FAILED] 任务执行失败:
- 任务ID: <task_id>
- 任务类型: <task_type>
- 失败原因: <失败类型>
- 失败详情: <详细错误信息>
- 当前重试次数: <retry_count>
- 需要的操作: <修复/重试/人工介入>

错误信息:
- <具体错误信息>
```

---

## 6. 状态汇报说明

Execute Skill 在完成任务后，必须向调用方汇报以下信息，供调用方更新状态文件：

### 任务完成时汇报

```json
{
  "task_id": "<task_id>",
  "task_name": "<task_name>",
  "status": "executed",
  "files_changed": ["<实际修改文件列表>"],
  "completed_at": "<ISO时间戳>",
  "task_summary": "{kb_dir}/<task-name>.md",
  "execution_details": {
    "new_files": <N>,
    "modified_files": <M>,
    "new_lines": <N>,
    "modified_lines": <M>,
    "new_tests": <N>
  }
}
```

**状态说明**：`executed` 表示代码开发已完成，等待 Review 和 Build 验证。调用方根据 Review/Build 结果决定最终状态（`done` / `failed`）。`reviewed` 和 `build_verified` 字段由调用方在 Review 和 Build 完成后设置。

### 任务失败时汇报

```json
{
  "task_id": "<task_id>",
  "task_name": "<task_name>",
  "status": "failed",
  "retry_count": "<当前值>",
  "last_error": "<失败类型>: <详细错误信息>",
  "needs_retry": true/false,
  "completed_at": "<ISO时间戳>",
  "failure_details": {
    "error_type": "<OUT_OF_SCOPE/QUALITY_VIOLATION/INTERFACE_INCOMPATIBLE/COMPILE_ERROR/LINK_ERROR/DEPENDENCY_MISSING/GN_CONFIG_ERROR>",
    "error_message": "<详细错误信息>",
    "files_involved": ["<相关文件列表>"],
    "suggested_fix": "<建议修复方案>"
  }
}
```

**注意**：Execute Skill **不直接更新状态文件**，只向调用方汇报结果，由调用方统一维护状态。
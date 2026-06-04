# Execute 阶段完成通知模板

本文件包含 Execute Skill 完成后的通知模板。

**重要约定**：所有过程文档存放在 `{kb_dir}/` 目录下，该目录由调用方指定。

---

## Execute Skill 完成通知模板

```text
[EXECUTE-COMPLETE] Execute 已完成:
- 任务ID: <task_id>
- 任务名称: <task_name>
- 任务类型: <task_type>
- 输出文件: {kb_dir}/<task-name>.md
- 已移交: Review Skill

任务执行要点:
- 实际修改文件数: <N>
- 新增测试用例数: <N>
- 验收标准自查: <全部满足/部分满足>

下一步: 等待调用方调用 Review 和 Build
```
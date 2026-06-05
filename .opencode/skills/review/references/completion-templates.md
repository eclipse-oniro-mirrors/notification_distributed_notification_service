# Review 阶段完成通知模板

本文件包含 Review Skill 完成后的通知模板。

**重要约定**：所有过程文档存放在 `{kb_dir}/` 目录下，该目录由调用方指定。

---

## Review Skill 完成通知模板

```text
[REVIEW-COMPLETE] Review 已完成:
- 任务ID: <task_id>
- 任务名称: <task_name>
- 检视结果: <通过/未通过>
- 检视日志: {kb_dir}/review-log.md

检视要点:
- 变更范围审计: <通过/未通过>
- 代码质量检视: <通过/未通过>
- 接口兼容性检视: <通过/未通过>

下一步: 
- 若通过: 进入 Build 进行编译验证
- 若未通过: 返回 Execute 进行修复
```

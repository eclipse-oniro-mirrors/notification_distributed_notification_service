# Doc 阶段完成通知模板

本文件包含 Doc Skill 完成后的通知模板。

**重要约定**：所有过程文档存放在 `{kb_dir}/` 目录下，该目录由调用方指定。

---

## Doc Skill 完成通知模板

```text
[DOC-COMPLETE] Doc 已完成:
- 功能总结: {kb_dir}/summary.md
- 测试报告: {kb_dir}/test-report.md
- 包含完整的功能说明、架构图、测试覆盖、审批历史

文档要点:
- 功能实现完整性: <简要说明>
- 测试覆盖率: <百分比>
- 验收标准满足情况: <说明>
- 遗留问题: <列出>

工作流已完成。

所有文档位置:
- {kb_dir}/summary.md (功能总结)
- {kb_dir}/test-report.md (测试报告)
- {kb_dir}/architecture.md (架构设计)
- {kb_dir}/dev-design.md (开发设计方案)
- {kb_dir}/plan.md (任务计划)
- {kb_dir}/review-log.md (检视日志)
- {kb_dir}/build-log.md (编译日志)
```
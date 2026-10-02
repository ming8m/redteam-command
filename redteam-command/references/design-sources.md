# 设计参考与原创边界

本 Skill 对业务假设、因果观察、任务分工、独立反证、证据谱系和恢复交接进行独立组织。文档、合成案例、附件格式与检查器以本仓库版本为准，不包含其他框架的 prompt、代码、payload 或知识库。

以下公开项目可用于比较 Agent 工作方式与实现取舍。链接固定到所参考提交，不能据此推断其当前功能、许可变化或安全性：

- [Strix：会话处理](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/core/sessions.py) 与 [报告路径](https://github.com/usestrix/strix/blob/007ed1a94e7dbf7b096c81e5b0354533ce94e0db/strix/tools/reporting/tool.py)。
- [Shannon：观察契约](https://github.com/KeygraphHQ/shannon/blob/a14c7944d87b30ed7bfecd4bad06562e24002b01/apps/worker/src/ai/reconciliation/contracts.ts) 与 [Agent 执行](https://github.com/KeygraphHQ/shannon/blob/a14c7944d87b30ed7bfecd4bad06562e24002b01/apps/worker/src/services/agent-execution.ts)。
- [PentAGI：工具执行器](https://github.com/vxcontrol/pentagi/blob/3cfe5cba4bf95e9562fd561ad2d44f0936ac7304/backend/pkg/tools/executor.go) 与 [环境探测](https://github.com/vxcontrol/pentagi/blob/3cfe5cba4bf95e9562fd561ad2d44f0936ac7304/backend/pkg/docker/sandbox.go)。
- [PentestGPT：计划](https://github.com/GreyDGL/PentestGPT/blob/e8b1bb77d1ac00329675cec3b060aba971ec1ac8/pentestgpt_agent/src/pentestgpt_agent/plan.py) 与 [执行循环](https://github.com/GreyDGL/PentestGPT/blob/e8b1bb77d1ac00329675cec3b060aba971ec1ac8/pentestgpt_agent/src/pentestgpt_agent/loop.py)。
- [CAI：并行上下文](https://github.com/aliasrobotics/cai/blob/6dc79257777f5f1c9500b4d2319935d34a47412e/src/cai/sdk/agents/parallel_isolation.py) 与 [guardrails](https://github.com/aliasrobotics/cai/blob/6dc79257777f5f1c9500b4d2319935d34a47412e/src/cai/agents/guardrails.py)。
- [PentestAgent：worker pool](https://github.com/GH05TCREW/pentestagent/blob/87d763a9c830597e9b8c1d56293300f6961beec2/pentestagent/agents/crew/worker_pool.py) 与 [Agent 执行](https://github.com/GH05TCREW/pentestagent/blob/87d763a9c830597e9b8c1d56293300f6961beec2/pentestagent/agents/base_agent.py)。

参考链接用于追溯设计讨论，不是再分发上游内容或背书。本仓库的 MIT License 仅适用于本仓库内容；使用上述项目应遵循各自许可。

## 本 Skill 的实际保证

- `check_claim.py` 使用 Python 标准库检查文件引用、定位、摘要、上下文、派生祖先、显式反证和复核字段。
- 合成单元测试验证这些工程行为，不访问外部目标或进行漏洞验证。
- 文字流程不会自动调度 Agent、隔离工具、阻断网络、接管任务或确认漏洞。
- 结构预检不能判断自然语言蕴含、证据记录者诚实性、等级是否正确或真实检出率。

没有模型检出率、误报率或成本对比结果；公开项目的关注度、基准或宣传成绩不代表本 Skill 的效果。

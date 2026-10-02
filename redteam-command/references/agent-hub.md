# 与多 Agent 编排器和 Agent Hub 配合

Skill 提供方法、任务简报和附件预检；编排器负责实际执行、消息与调度。保留编排器自身输出协议、任务状态和权限配置，不用 Skill 文本改写它们。

## 通用接入

1. 主控读取 [Skill 入口](../SKILL.md)，从用户会话恢复 `skill-maintenance`、`offline-review` 或 `authorized-assessment` 的具体范围。
2. 使用 [任务简报](../assets/task-brief.md) 给每项子任务明确问题、owner、输入、验收、预算和停止条件。继承主任务限制，记录逻辑角色与实际 Agent ID 的映射。
3. 给执行者实际入口内容及本任务所需参考材料。仅能接收文本的 API 模型无法凭文件路径读取文档；CLI Agent 的文件权限和工具能力也需实际核对。
4. 主控核对依赖交付与共享资源，保留独立复核职责；结束后按原始证据收敛，不把编排器 succeeded 当作漏洞确认。

一个 Agent 可以承担多个串行职责。没有多 Agent 能力时如实使用串行方式；提示词里列出角色不等于实际委派。分工与横向协查见 [team-playbook.md](team-playbook.md)。

## Agent Hub

通用项目为 [ming8m/agent-hub](https://github.com/ming8m/agent-hub)。将主任务、Skill 入口和按需参考内容交给其配置的执行者，可搭配现有执行或协作方式使用。原始仓库是否包含 Skill 加载器，取决于所用版本，不能仅因安装本 Skill 就声称已自动接入。

独立发布的 [ming8m/redteam-agent-hub](https://github.com/ming8m/redteam-agent-hub) 默认装载本 Skill。该版本的工作预设、加载范围与执行边界以其仓库 README 为准；这里不要求使用它，其他编排器也可应用相同方法。

提示词加载和工作方式限制属于执行指令，不提供网络过滤、容器隔离或文件权限隔离。实际 CLI、API 模型和外部工具的能力由调用方环境决定。

## 推荐任务示例

```text
工作方式：offline-review。
输入：本轮提供的接口定义、指定源码版本和脱敏日志。
目标：核对业务权限约束、输入处理机制及现有结论的反证。
分工：请求契约 owner、机制 owner、独立 reviewer。
限制：不访问目标，不重放请求，不验证漏洞；衍生任务继承限制。
交付：原始来源、可复算定位、支持/反驳/未知、必要前提和下一项材料。
```

Hub 的 run/task ID 与案件或其他任务系统的 ID 分别记录并映射。维护任务只做工程验收，不为通过安全评估门禁生成虚构资产、覆盖或发现。调用方有正式完成门禁时另行执行并报告真实结果。

# redteam-command

**红队协同指挥 Skill v3.2**：把业务约束、调查假设、任务分工、原始证据、反证和独立复核放在同一条工作链中。

这个 Skill 可以独立使用，也可以搭配多 Agent 编排器。它提供协作方法和可移植的证据附件检查器，不要求特定模型、总线、私有运行时或任务状态库。

## 它适合做什么

- 根据正常业务、接口和实现材料形成可证伪假设。
- 按请求契约、机制与影响、独立反证分派任务，明确 owner、依赖、预算和停止条件。
- 支持维护、离线审阅和已有授权范围内的安全评估；所有子任务继承用户本轮的限制。
- 区分当前实验、源码证明和历史观察，避免把状态码、扫描标签或 Agent 摘要当作漏洞证明。
- 检查证据引用、摘要、上下文、反证与复核材料，帮助发现附件不完整或相互矛盾的问题。

## 安装与调用

下载本仓库或运行：

```sh
git clone https://github.com/ming8m/redteam-command.git
```

将仓库内的 `redteam-command/` 整个目录放入你的客户端支持的 Skill 目录，再让客户端重新加载。支持 Skill 的客户端从 `SKILL.md` 读取入口；其他客户端可以显式加载入口及当前任务需要的参考文件。

示例：

```text
使用 $redteam-command，仅离线审阅我提供的接口定义和源码。
安排请求契约、机制分析和独立反证三个任务，给出证据与缺口。
本轮不访问目标、不重放请求、不验证漏洞。
```

Skill 中的主动评估方法需要具体任务的授权与范围。安装或加载 Skill 本身不授权任何目标操作。

## 搭配多 Agent

主控先明确本轮工作方式，再给每项任务一个 owner、具体问题、输入、验收和停止条件。请求契约与机制分析可在前提允许时并行；独立复核保留单独职责。涉及同一账号、对象或限额的变更动作串行。

可使用原生子 Agent、CLI Agent、API 模型或已有编排器。没有实际多 Agent 能力时按同样的问题串行执行，并如实说明。角色描述不等于实际委派。

任务简报和动作记录分别见 [task-brief.md](redteam-command/assets/task-brief.md) 与 [action-record.md](redteam-command/assets/action-record.md)。详见 [协作规则](redteam-command/references/team-playbook.md)。

## 搭配 Agent Hub

[Agent Hub](https://github.com/ming8m/agent-hub) 可以承担执行与协作编排。将 Skill 入口和当前任务所需参考内容交给所选 Agent，并把本轮限制放入主任务与子任务简报。使用仅能接收文本的模型时，应提供实际文件内容，不能只给一个文件路径。

配套发布的 [Redteam Agent Hub](https://github.com/ming8m/redteam-agent-hub) 默认装载这个 Skill，可直接使用其离线红队工作预设。原始 Agent Hub 仓库是否自动加载 Skill，以该仓库自身文档和版本为准。接入说明见 [agent-hub.md](redteam-command/references/agent-hub.md)。

编排器的任务成功表示执行流程结束。漏洞是否成立、严重性和最终交付仍需要原始证据与语义复核。Skill 指令不提供网络过滤、沙箱或权限隔离。

## 离线检查器

要求 Python 3.10 或更新版本，仅使用标准库：

```sh
python -B redteam-command/scripts/check_claim.py --case <案件目录> --claim <案件内附件.json>
python -B -m unittest discover -s redteam-command/scripts -p test_check_claim.py -v
```

检查器只读文件、不联网、不写任务状态。退出码 0 表示附件通过结构与引用预检，不证明证据内容真实或漏洞成立。格式与限制见 [claim-format.md](redteam-command/references/claim-format.md)。测试使用合成夹具，不执行目标验证。

## 内容与许可

公开包只包含通用方法、模板、可移植检查器及其合成测试，不包含私有执行配置、凭据或真实案件材料。参考项目及原创边界见 [design-sources.md](redteam-command/references/design-sources.md)。本仓库以 [MIT License](LICENSE) 发布。

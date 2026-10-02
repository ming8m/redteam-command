# 高影响结论的附件预检

这是发现附件格式，独立于调用方任务系统的状态模型。主控准备正式结论时生成附件，先运行 `scripts/check_claim.py`，再进行语义复核。检查器不会调用确认接口。退出码 0 表示元数据符合约束；不能因此自动填写 confirmed。

候选阶段可从 [附件模板](../assets/claim-template.json) 开始。缺项如实保留；正式结论绑定原始证据和复核附件。文件都保存在独立案件目录内，命令中的 `--case` 为案件绝对目录，`--claim` 为该目录内 JSON 的绝对路径或相对案件路径。脚本只使用 Python 标准库，读取文件、输出不含证据正文的 JSON，返回 0 或 1，不联网、不写文件、不读密钥配置。

## 顶层字段

| 字段 | 含义 |
|---|---|
| schema_version | 新附件为整数 2；既有整数 1 兼容读取，不自动补字段 |
| claim_id / statement | 稳定 ID 与具体待裁定命题；一个附件只表达一个边界突破 |
| kind | sqli / server_execution / authorization / other |
| mode | current 当前实验 / source 源码证明 / historical 历史观察 |
| disposition | candidate / confirmed；此处表示拟交付结论，不直接修改运行状态 |
| claims_current_exploit | 是否声称当前利用成立；source/historical 必须 false |
| owner | 发现者标识，与复核者区分 |
| context_id | 绑定环境、版本、路由/方法、身份条件及时间窗口的语义标识；相关证据使用同一标识 |
| origin | hint_level 为 none/class/system_class/exact_location/reproduction，independent_discovery 为布尔值；有提示不能声称本次是独立发现 |
| evidence / checks | 下述附件和判据 |
| progress | no_new_information_rounds 为非负整数，next_action 为 probe/restore_prerequisite/report/review；changed_prerequisite_refs 默认为空 |
| state_changed | confirmed 必填布尔值；有变更则必须支持 cleanup |
| review | confirmed 必填：reviewer、mode（offline/independent_replay）、refs；引用的全部祖先必须完整且 context 一致；重放另需 replay_refs |

`context_id` 一致只证明声明相同，复核者仍必须读原始请求的真实环境、身份、方法与编码。模型不能给不兼容证据改标签以通过检查。提示前已独立发现同一问题时，拆成带快照的提示前主张与提示后补充记录，避免来源归属混淆。

## 版本 2：假设、反证与等级理由

`hypothesis` 记录一个待推翻的业务判断，六项字段为：

| 字段 | 应说明 |
|---|---|
| constraint | 哪项身份、对象、动作或状态关系应成立，依据是什么 |
| failure_boundary | 在哪个实际入口或交接点可能丢失这项约束 |
| minimal_observation | 用最少动作观察什么业务结果；只看响应码不够 |
| negative_control | 约束被正确实施时能得到什么等价对照 |
| falsifier | 哪种观察会推翻当前解释，及其适用前提 |
| evidence_threshold | 支持确认需要哪些原始材料和效果证据 |

`hypothesis.refs` 绑定业务依据或实现来源；准备 `probe` 或拟 `confirmed` 时六字段必须非空，refs 及祖先完整、context 一致。候选选择 restore_prerequisite/report/review 时六字段可为 null 或空字符串，refs 可空；字段键仍需齐全。这让缺口可如实保留，不用虚构对照。结构齐全不是完成实验或证明约束真实。

`contradictions` 是必需的反证列表，无已知反证时为 `[]`。每项有唯一 `id`、原始 `refs` 和 `resolution`（unresolved/explained/refuted）；解释或驳回时还需非空 `reason` 与 `resolution_refs`，该引用及祖先须完整且 context 一致。拟 confirmed 不能留 unresolved，也不能有任何 checks.result 为 contradicted。保留原始不利观察；后续处理不能靠删掉反证或改标签完成。检查器只能检查显式登记项，复核者还须主动发现遗漏与不真实的消解理由。

版本 2 拟 confirmed 另有 `assessment`：`demonstrated_capability`、`affected_objects`、`preconditions`、`severity_basis` 为非空文字；`severity` 为 unrated/info/low/medium/high/critical，`refs` 绑定完整且同 context 的材料。unrated 允许“已证实但等级未裁定”；severity_basis 标明平台规则、通用规则或技术初评。填入 high 不能证明高危，检查器不算分，语义定级见 [reasoning.md](reasoning.md)。

示例仅表达反证流转的字段关系：

```json
{"id":"counter-01","refs":["denial-01"],"resolution":"unresolved"}
```

旧版本 1 不要求这些新字段，不能宣传它已接受版本 2 的完整反证检查。旧附件重新参与当前确认时建立新版本 2 附件并真实复核，保留旧文件与摘要。

## 证据项

每项包含 `id`、案件内 `path`、真实 `sha256`、`scope`（current/source/historical）、`context_id`、`complete`（是否完整）与 `form`（raw/derived）。派生项以 `derived_from` 引用父 evidence ID，可以多层；检查器检查整条祖先链和循环引用。脱敏副本注明处理范围，影响语义的删节不能声明完整。

`locator` 必须且只能用一种定位：

```json
{"json_pointer": "/Content/2"}
```

或一基起始、闭区间的 `{"lines": [10, 18]}`。JSON Pointer 遵循 `~0` 和 `~1` 转义，空字符串指整个 JSON。检查器逐项读取 UTF-8/UTF-8 BOM 的 JSON 或文本，包括派生祖先；原始二进制不能直接加入这条 evidence 链。二进制或其他编码原件另保留受控引用及转换过程，产生可读附件供审阅；不能把转换摘要冒充原文，也不能声称预检已核验未进入链的原件。

独立重放证据另有 `actor` 和 `role: "replay"`；必须是复核者实际产生的 current、完整、raw 记录。仅另一 Agent 重读原响应应写 offline。整个响应有凭据时，保留受控原件，不把凭据复制进本 JSON；引用的可读材料采用保留所需语义的脱敏证据。

## checks：什么结论必须有什么证据

每项形式为 `{"result": "supported", "refs": ["evidence-001"]}`。结果还可为 missing、contradicted、not_applicable；supported 必须有引用，其全部祖先完整且 context 一致，包括自定义判据，不能用无证据的布尔值通过。其他结果允许空引用。检查器校验引用存在与完整性，不理解其文字是否支持命题。

confirmed 的通用要求是 `impact`、`alternatives`，独立 reviewer 和复核材料；若 state_changed 为 true，还要 `cleanup`。各方式额外要求如下：

| 方式 | 必须 supported 的 checks |
|---|---|
| current | contract、baseline、mapping、effect、control，且这些引用及其全部祖先必须为 current |
| current + sqli | 再要求 sql_semantics，引用必须 current |
| current + server_execution | 再要求 implementation、reachability、execution_witness；后两项引用必须 current |
| source | implementation、mapping、reachability、version_applicability |
| historical | historical_semantics、time_scope |

执行结论另需 `witness_kind` 为 correlated_server_telemetry 或 controlled_execution_effect，响应回显不算执行见证。正常基线与 SQL 结构变化、权限边界和执行结果必须分别审阅；把同一无关文件引用到所有 checks 仍然是不合格结论，机器无法代替这个判断。

两个实验无信息增量后仍安排 probe 时，必须用 changed_prerequisite_refs 绑定新前提，并在 `prerequisite_change` 中以相同引用集解释改变；其祖先链也必须完整且 context 一致。没有前提变化而用户明确要求有限继续时，以 `bounded_continuation` 绑定用户要求、限制及新实验的判别理由。继续要求不是漏洞证据。

## 复核者需要补的语义判断

阅读原文核对：契约来源是否真实；基线是否业务成功；输入映射是否对应；对照是否排除正常业务/缓存/网络/身份差异；见证是否发生在目标；版本和时钟是否可比较；实际影响是否达到所报级别；限制是否同步到报告标题。

`impact` 写成 supported 只是作者声明，不能凭字段齐全取得中危或高危。等级另外按 [定级规则](reasoning.md#漏洞成立与严重性分别裁决) 审阅具体新增能力、对象敏感性与适用标准。当前检查器不实现严重性评分，也不验证平台收录资格。

脚本不进行自然语言蕴含判断、不验证证据记录者诚实性、不自动比对多份报告、不检查真实目标，也不是防恶意文件竞态的执行隔离层。定位有效与摘要相符仅保证本次读取的可追溯性。证据文件在预检后变动需重检；正式结论另外绑定实际审阅摘要。通过预检后，语义复核仍可驳回。调用方已有完成门禁时另行执行并保留真实结果；附件预检不替代该门禁。

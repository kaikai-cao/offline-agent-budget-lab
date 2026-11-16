# E4.8.3 — 授权凭证与 Agent 工具执行回执绑定

**阶段目标：** 将签名 Lease Grant、离线预算序号、精确工具请求、工具 Schema Hash 与执行回执绑定为一条可验证链。

**安全边界：纯软件模型。** 本包不调用 TBS、不连接 TPM、不发送 TPM 命令、不修改 E4.7.3，也不修改现有 `agent-exec-binding-mvp`。支持两种预算路径：保留 E4.8.2 的单 Lease Durable Broker 路径；另由 `src/global_budget_adapter.py` 接入 E4.8.4 的 Multi-Lease Global Budget Broker。多 Lease 路径仍使用单机共享 SQLite Journal、JSON 文件计数器和文件锁，不代表真实 TPM 或多主机能力。

## 运行环境

- Python 3.10+
- `cryptography`（Ed25519 签名/验签）
- 其余依赖均为 Python 标准库

在项目根目录解压本包后，打开 PowerShell：

```powershell
Set-Location -LiteralPath "D:\Research\offline-agent-budget-lab\e4_8_3_execution_binding"

python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

不需要管理员权限。这里的安装命令只在缺少 `cryptography` 时需要执行。

## 这轮做了什么

1. Issuer 使用 Ed25519 私钥签发 Lease Grant；Gateway 使用独立配置的 Issuer 公钥验签。
2. Grant 绑定 `grant_id`、`lease_id`、`subject_id`、`audience`、`context_digest`、有效期、额度和允许的 `tool_name -> schema_hash`。
3. Gateway 从可信 Tool Adapter 读取实际 Schema Hash，不接受调用方提交的 Schema Hash。
4. 请求摘要绑定 Grant Digest、操作 ID、主体、上下文摘要、工具名、Schema Hash 和规范化参数。
5. E4.8.2 Durable Broker 分配持久化单调序号；同一 `operation_id + request_digest` 重放返回同一预算回执，不再次递增。
6. Tool Adapter 接收同一 `operation_id`，执行后生成结果摘要；Gateway 对包含预算序号和结果摘要的执行回执进行 Ed25519 签名。
7. 执行状态写入 SQLite；跨进程 Gateway Lock 覆盖检查、预算分配、工具调用和回执落盘。

## 测试覆盖

- 真实的 Ed25519 Grant 签发/验签；篡改 Grant、过期 Grant 被拒绝。
- 主体、Context、Audience、工具 allowlist、Schema Drift、Broker Lease/Quota 不匹配。
- 请求参数或 Operation ID 绑定变化被拒绝。
- 执行回执签名与结果摘要校验；篡改回执后验签失败。
- 多个操作取得不同预算序号；同一操作重放不重复消费。
- D8.2 将多个签名 Execution Lease Grant 绑定到 E4.8.4 的签名 Global Lease Grant，并共享全局序号。
- D8.3 覆盖跨 Lease operation ID 竞争、单 Lease 额度耗尽隔离、Gateway 重启回执恢复，以及撤销/过期后的精确操作恢复。
- 两个独立进程并发提交同一 Operation ID，共享一张签名回执和一次工具效果。
- 预算分配后、Dispatch Intent 后、工具效果后、Receipt Commit 后的崩溃恢复。
- 外部工具具备 operation_id 幂等能力时，可安全恢复；不具备幂等/状态查询能力时，进入 `INDETERMINATE`，不自动重复调用。
- 额度耗尽后拒绝第二次工具调用，计数器不继续递增。

## 结果状态

```text
ALLOCATING
    -> BUDGET_CONSUMED
    -> DISPATCHING
    -> COMMITTED
```

终态/故障状态：

- `FAILED_NO_BUDGET`：Broker 明确确认未分配额度或额度已耗尽。
- `INDETERMINATE`：预算锚点不一致，或工具在 Dispatching 后缺少可靠幂等/状态查询，无法安全判断外部效果。

只允许在同一 Grant、同一 Operation ID、同一请求摘要下恢复。存在其他未决操作时，Gateway 暂停接收新操作，先恢复旧操作。

## 重要限制

- 旧版 `DurableCounterBroker` 路径仍然是单 Lease。多 Lease 路径由 E4.8.4 `GlobalBudgetBroker` 和 `GlobalBudgetExecutionAdapter` 提供：每个 Execution Grant 必须与同一 Issuer 签发的 Global Lease Grant 精确配对；所有参与者共享同一全局 Journal、JSON Counter、Counter Lock 和 Broker Lock。该路径不是 TPM Counter 分片或硬件实现。
- Ed25519 私钥在测试中由进程临时生成。实际部署必须把 Issuer/Gateway 密钥放进独立可信密钥管理边界，并稳定管理轮换和公钥信任根。
- 执行回执是 Gateway 对 Broker 结果和工具结果的签名陈述；它不是 TPM 对某条 NV_Increment 命令的直接密码学证明。
- SQLite 执行账本、模拟器 Counter 文件和 Tool Adapter 测试数据库均为软件状态。当前模型不抵御管理员替换程序、回滚/篡改全部本地文件、内核攻击或跨主机克隆。
- `SQLiteIdempotentTool` 是一个测试替身，原子地保存 `operation_id` 和结果。真实外部工具必须自己支持幂等键或可靠状态查询，Gateway 本身不能创造 exactly-once 外部副作用。
- 预算序号在工具调用前消耗。工具拒绝、失败或崩溃可能导致预算额度被消耗但没有成功回执；这是 fail-closed 设计的代价。
- Grant 在每次调用/恢复时都重新检查有效期。若恢复时 Grant 已经过期，当前模型拒绝继续并保持 fail-closed，需要上层人工策略处理未决操作。
- 测试覆盖的是定义好的进程中断点，不是物理断电、文件系统损坏或硬件掉电耐久性测试。

详细协议、威胁模型、状态迁移和验收边界见 `docs/e4-8-3-design-and-test-plan.md`。

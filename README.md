# Offline Agent Budget Lab

面向多 Agent 离线工具执行场景的预算约束、可信状态与执行回执研究实验室。

本项目研究一个核心问题：

> 当 Agent 无法持续连接中心授权服务时，如何限制其工具调用预算，防止授权凭证重放、状态回滚、并发超额消费，并在网络恢复后完成可信对账？

项目采用渐进式研究路线：从软件预算账本和执行回执开始，经过攻击实验、状态信任比较和架构设计，再评估真实硬件可信状态原语。

## 1. Research Scope

当前研究围绕以下问题展开：

- **Budget allocation:** 如何分配和约束多个 Agent / Lease 的离线预算？
- **Execution authorization:** 如何将授权主体、执行上下文、工具及 Schema 绑定到具体操作？
- **Replay and rollback:** 如何识别请求重放、状态复制和旧状态恢复？
- **Durable execution:** 崩溃发生在预算分配、工具执行和回执提交之间时，如何恢复？
- **Reconciliation:** 如何利用独立可信锚点验证执行证据并完成最终对账？
- **Hardware trust:** TPM / TEE / 安全存储能够提供哪些可信状态能力，又有哪些边界？

本项目是研究原型和实验记录，不是生产级 Agent 安全框架，也不构成形式化安全证明。

## 2. Research Evolution

| Stage | Focus | Main outcome |
|---|---|---|
| E0 | Budget ledger and receipts | 本地预算账本、签名凭证、哈希链与最终对账模型 |
| E1 | Attack experiments | 验证授权与执行者信任绑定中的攻击面，并通过 E1.1 修正执行者公钥信任来源 |
| E2 | State trust comparison | 比较本地软件状态、共享原子状态和单调状态抽象 |
| E3 | Architecture freeze | 冻结离线预算分配、可信执行、状态更新和最终对账的候选架构 |
| E4 | Hardware feasibility | 探测 TPM 能力，并开展受控 NV Counter 持久性实验 |
| E4.8.2 | Durable broker | 文件模拟计数器、SQLite 持久化账本和跨进程单写者 Broker |
| E4.8.3 | Execution binding | 将签名 Lease Grant、预算序号、工具请求、Schema Hash 和执行回执绑定 |

各阶段的具体假设、实验过程和结果以对应目录中的文档为准。

## 3. Repository Structure

```text
.
├── src/budget_lab/              # E0 基础预算与对账实现
├── tests/                       # E0 回归测试
├── docs/                        # E0-E4 设计与实验文档
├── e4.5_nv_public_probe/        # TPM NV 只读探测
├── e4_7_1_design_review/        # NV Counter 设计审查
├── e4_7_2_readonly_preflight/   # 写操作前置只读检查
├── e4_7_3_counter_test/         # 受控真实 TPM NV Counter 实验
├── e4_7_nv_counter_design/      # NV Counter 设计材料
├── e4_8_2_durable_broker/       # 持久化 Broker 软件模型
├── e4_8_3_execution_binding/    # Grant 与工具执行绑定模型
├── e4_8_counter_binding_model/  # Counter 绑定协议模型
└── results/                     # 实验结果与归档证据
```

## 4. Quick Start

### Requirements

- Python 3.10+
- Windows PowerShell（部分 TPM 探测脚本仅适用于 Windows）
- `cryptography`，版本见根目录 `requirements.txt`

安装依赖：

```powershell
python -m pip install -r requirements.txt
```

运行基础回归测试：

```powershell
.\run_tests.ps1
```

运行 E1 攻击实验：

```powershell
.\run_e1_attacks.ps1
```

运行 E2 状态信任实验：

```powershell
.\run_e2_tests.ps1
```

运行 E4.8.2 Durable Broker 测试：

```powershell
Set-Location .\e4_8_2_durable_broker
python -m unittest discover -s tests -v
```

运行 E4.8.3 Execution Binding 测试：

```powershell
Set-Location ..\e4_8_3_execution_binding
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

各子项目也提供独立 README 和测试说明。运行前请先阅读对应文档。

## 5. Important Hardware Safety Warning

**WARNING: E4.7.3 contains real TPM NV write operations.**

目录 `e4_7_3_counter_test/` 中的脚本不是普通软件模拟实验，涉及真实 TPM 2.0 NV Index 操作，包括：

- `TPM2_NV_DefineSpace`
- `TPM2_NV_Increment`
- `TPM2_NV_UndefineSpace`

这些操作会改变 TPM 持久化状态并消耗 NV 资源。

不要将该目录中的脚本作为常规测试或 CI 测试运行。

运行前必须：

1. 阅读 `e4_7_3_counter_test/README-E4.7.3.txt` 和 `README-RECOVERY.txt`。
2. 阅读对应实验设计、恢复和清理文档。
3. 确认设备、TPM 层级授权、NV Index 和恢复条件。
4. 理解脚本的人工确认步骤及中断后的恢复流程。
5. 只在明确授权、可控的实验设备上执行。

不要随意修改候选 NV Index、授权值、实验状态文件或清理逻辑。遇到状态不确定时，不要重复发送写命令。

本仓库记录的 E4.7.3 实验已完成，并已验证专用测试 NV Index 清理结果。**不需要为了复现仓库而再次执行该实验。**

其他 E4.4、E4.5、E4.6 探测脚本的操作边界不同，运行前也应阅读各自说明。

## 6. Security and Evidence Boundaries

需要特别区分以下事实：

- E0-E2 的测试结果验证的是当前软件模型和已实现测试，不代表真实硬件安全性。
- E3 是候选架构设计，不是已经完成的 TEE 实现。
- E4.7.3 是特定 TPM、特定 NV Counter 配置、一次递增和一次正常 Windows 重启下的实机实验，不应推广为普遍安全结论。
- E4.8.2 使用文件模拟计数器和 SQLite，不是真实 TPM 单调计数器。
- E4.8.3 是纯软件执行绑定模型，不提供硬件防回滚或真实外部工具 exactly-once 保证。
- 外部工具的 exactly-once 效果需要工具自身提供可靠幂等键或权威状态查询；仅靠 Gateway 无法保证。

测试通过表示对应测试用例通过，不等价于形式化验证、统计性安全证明或生产环境安全认证。

## 7. Current Research Direction

当前工作重点是继续验证离线预算状态与 Agent 工具执行之间的绑定关系，尤其关注：

1. 授权凭证与具体执行请求的不可替换绑定；
2. 预算分配与工具执行之间的崩溃恢复语义；
3. 工具副作用不确定时的 fail-closed 处理；
4. 单调状态原语与上层执行协议之间的信任边界；
5. 多 Lease / 全局预算约束下的最终对账。

后续研究结论应以可复现实验、明确的威胁模型和可核查的证据为依据。

---

**Project status:** Research prototype and experimental archive.

**License:** No license specified. All rights reserved by default.

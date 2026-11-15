# E4 Hardware Feasibility Assessment v0.1

## 面向多 Agent 离线工具执行的可信状态硬件能力核查

**状态：** 初步能力评估；不构成硬件安全证明或采购建议  
**阶段目标：** 判断现有 Windows PC 能否验证 TPM 单调计数器原语，并筛选后续真实离线可信状态实验平台。  
**本阶段不做：** 创建/删除 TPM NV index、执行 TPM NV increment、修改 BIOS/UEFI/TPM 配置、清除 TPM、购买设备、编写 TEE 适配器或修改 E0/E1/E2 代码。

---

## 1. E3 所需硬件能力

E3 的可信状态机制至少需要区分以下能力，不能把它们统称为“有 TEE”：

1. **设备绑定密钥：** 执行者密钥不可被普通软件导出，并且能绑定设备或可信执行环境。
2. **执行隔离：** 恶意宿主 OS / 管理员不能任意读取、修改或绕过预算状态转移逻辑。
3. **防回滚持久状态：** 断电、重启、磁盘快照恢复后，旧预算状态不能被重新接受。
4. **原子状态更新：** 预算状态更新能够给出断电/崩溃时的原子性或明确的恢复语义。
5. **远程/本地证明：** 验证方能判断执行代码、设备状态及密钥来源是否满足策略。
6. **可用性与恢复：** 硬件不可用、计数器耗尽、设备丢失或证明失败时，系统能够 fail closed，并明确未结算预算如何处理。

单一硬件原语通常不能覆盖上述全部能力。

## 2. 候选技术判断

### 2.1 当前 Windows PC：TPM 2.0 NV Counter

TPM 2.0 规范定义了 NV Counter Index。该类型的计数器只能通过 `TPM2_NV_Increment()` 修改，规范要求计数值不回退，并处理删除后重新定义同名计数器的回退问题。它适合提供单调版本号/epoch 原语。

但 TPM NV counter **不是通用的原子状态数据库**：它不能单独原子提交“预算状态文件 + 外部工具效果”；也不能单独隔离整个 Python Executor。若计数器推进成功、随后磁盘状态写入失败，必须由上层协议检测不一致并 fail closed。

Windows 的 TPM Base Services (TBS) 对 TPM 2.0 命令采用允许列表机制。`Get-Tpm` 只提供 TPM 存在、就绪和厂商等信息，不证明某个 NV 命令对当前 Windows 构建、驱动、用户权限和 TPM 固件一定可用。因此本阶段只做只读探测，不执行 NV 写命令。

**对当前工作站的初步判断：** 已有记录中的 CPU 是 Intel Core i7-14700。Intel 产品规格页列出了 Intel Trusted Execution Technology、Boot Guard、TME-MK、VT-x/VT-d 等特性，但没有列出 Intel SGX；Intel SGX 支持说明要求在具体处理器规格和 OEM BIOS 中单独确认，SGX2 页面列出的平台家族并不包括该 14 代桌面型号。因此不应把这台机器预设为可运行 SGX enclave。TXT/Boot Guard/TPM 不能直接等同于进程级 enclave。

**定位：** 可作为 TPM 单调计数器、设备密钥和启动状态测量的初步实验平台；不能仅凭 TPM 证明恶意 OS 下的 Executor 代码隔离。

### 2.2 Arm TrustZone + OP-TEE + eMMC RPMB

OP-TEE 文档区分普通 REE 文件系统和 RPMB 后端。其可信存储操作要求原子更新；当配置 `CFG_RPMB_FS=y` 时，防回滚由 TEE 控制；若 `CFG_RPMB_FS=n`，该配置下没有相应的回滚保护。

这条路线更贴近 E3 的离线场景：TEE 内执行预算状态转移，RPMB 作为防回滚持久化后端。但保证依赖具体 SoC、可信启动链、TEE BSP、真实 eMMC RPMB 支持、RPMB key provisioning 和实际构建配置，不能仅凭开发板宣传页写成“支持 OP-TEE”就认定满足要求。

**定位：** 当前最匹配的真实离线可信状态候选路线。选择具体板卡前，必须逐项核实真实 RPMB、OP-TEE 版本/BSP、可信启动和可复现的 `CFG_RPMB_FS=y` 构建。

### 2.3 Android TEE / StrongBox KeyMint

Android Keystore 可以将密钥绑定到 TEE 或 Secure Element，保持密钥材料不可导出。StrongBox 提供独立安全硬件和安全存储能力。

但 KeyMint 的 `ROLLBACK_RESISTANCE` 语义需要精确理解：其定义是密钥删除后硬件确保该密钥不能再次使用；这不等于向任意应用提供可更新、可查询、可事务提交的通用单调预算数据库。

**定位：** 适合设备绑定密钥、签名和密钥证明研究；仅凭 StrongBox 不足以满足 E3 的通用预算状态回滚防护。

### 2.4 AWS Nitro Enclaves

Nitro Enclaves 支持基于测量值的加密证明，可用于验证 enclave 身份和授权代码。但官方文档明确 enclave 没有持久存储，也没有外部网络，只能通过与父实例的本地 socket 通信。

**定位：** 可作为远程证明/隔离执行的云端对照；不适合作为本项目“断网期间持续保存可信预算状态”的首选边缘执行节点。若状态存放在父实例磁盘，仍需另行处理父实例快照回滚。

## 3. 能力矩阵

| 候选 | 非导出密钥 | 执行隔离 | 防回滚持久状态 | 原子持久更新 | 证明能力 | 与离线场景匹配度 |
|---|---|---|---|---|---|---|
| Windows TPM 2.0 NV Counter | 可提供 TPM 内密钥原语，需验证平台配置 | 不提供通用进程 enclave | 单调 counter 原语 | 不提供“counter + 任意文件/外部效果”的端到端原子事务 | PCR/TPM quote 路线需另行设计 | 中：适合原语实验，不是完整方案 |
| Arm OP-TEE + RPMB | TEE 内密钥能力，依 SoC 实现 | TrustZone TEE | RPMB 后端并启用 `CFG_RPMB_FS=y` 时可提供文档定义的 rollback protection | OP-TEE Trusted Storage 支持原子文件操作；仍需验证实际平台实现 | 依赖 SoC/启动链/attestation 方案 | 高：最匹配的候选 |
| Android StrongBox | 是，依设备实现 | 独立安全硬件 | KeyMint 特定 key rollback resistance，不等于通用状态计数器 | 不应假定应用任意状态事务能力 | Key attestation 能力依实现 | 中低：适合密钥，不是预算账本主路线 |
| AWS Nitro Enclaves | 可经 KMS/attestation 工作流使用受控密钥 | 是 | enclave 本身无持久存储 | enclave 内没有持久存储事务 | 有测量值 attestation | 低：云端对照，不适合断网持久状态 |

## 4. 当前工作站的只读探测目标

先只确认：

- CPU、主板/整机型号、BIOS 版本；
- Windows 版本/build；
- TPM 是否存在、Ready 状态、制造商 ID 和固件版本；
- Secure Boot 当前状态；
- Hypervisor 是否运行。

这些信息只能缩小候选范围，不证明 NV increment 命令可用，也不证明 TPM 具备对应用执行代码的隔离能力。

`probe_e4_platform_readonly.ps1` 只调用只读系统查询；不会定义/写入/删除 NV index，不会 increment counter，不会清除 TPM，也不会修改 BIOS/UEFI 设置。

## 5. 实机验证的分阶段门槛

### Gate E4-A：发现硬件

通过只读探测取得实际整机/主板型号、TPM 厂商与版本、Secure Boot 状态。若 `TpmPresent=False` 或 TPM 未 Ready，则暂停 TPM NV 实验，先查 BIOS/OEM 配置，不执行初始化或清除操作。

### Gate E4-B：确认 NV Counter 能力与权限

确认 TPM 的 NV counter 能力、可用 NV index 资源、授权策略、Windows TBS command allowlist 和访问主体。不得把 `Get-Tpm` 的成功输出当作 `TPM2_NV_Increment` 已获准。

只有在明确数据备份、恢复流程、NV index 所有权/授权、使用频率和回滚后果后，才可单独设计最小 NV 实验。不得在当前阶段执行写操作。

### Gate E4-C：评估端到端安全性

即使 TPM counter 可用，仍需回答：

- 谁执行预算状态转移代码？若在普通 OS 中，恶意管理员能否绕过它？
- TPM counter 与磁盘/WAL 更新之间发生崩溃，如何恢复？
- 设备密钥如何绑定到具体软件度量值和策略？
- 如何处理 counter 增量已经成功但结果尚未持久化的情况？

若不能给出 fail-closed 恢复协议，则 TPM 只能视为单调计数原语，不是完整可信状态方案。

### Gate E4-D：决定真实离线 TEE 平台

优先评估能真实启用 OP-TEE RPMB secure storage 的 Arm 开发平台。采购前必须有官方或厂商可核验资料证明：SoC TrustZone、OP-TEE BSP、eMMC RPMB、可信启动链、RPMB key provisioning 和构建配置均可实现。模拟器或普通文件系统不能替代实机 RPMB 防回滚证据。

## 6. 当前结论

1. 当前 Windows PC 值得先进行只读硬件探测；若 TPM 2.0 Ready，可把它作为单调计数器原语候选，但不把它当作完整 TEE。
2. 不将 Intel SGX 作为当前 i7-14700 工作站的既定路线；先以 Intel ARK/BIOS 的明确规格为准。
3. 对真实离线执行，优先研究 Arm TrustZone + OP-TEE + RPMB；具体板卡尚未选定，暂不采购。
4. Android StrongBox 作为设备密钥/签名对照；AWS Nitro Enclaves 作为云端远程证明对照，均不是首选离线状态平台。
5. 暂不开发 ZK 电路。当前最关键的是状态防回滚、原子恢复和真实执行效果之间的安全边界。

## 7. 本阶段验收标准

- [ ] 运行只读探测脚本并取得本机实际硬件信息。
- [ ] 根据输出判断 TPM 2.0 是否存在且 Ready。
- [ ] 明确区分 TPM counter、TEE 执行隔离和 RPMB rollback-protected storage。
- [ ] 不执行任何 NV 写命令、不清除 TPM、不修改 BIOS。
- [ ] 在取得具体主板/整机型号后，再决定是否做 TPM 原语实验，或直接转向 OP-TEE/RPMB 开发板评估。

---

## References

1. Intel, Core i7-14700 Product Specifications: https://www.intel.com/content/www/us/en/products/sku/236781/intel-core-i7-processor-14700-33m-cache-up-to-5-40-ghz/specifications.html
2. Intel, Which Platforms Support Intel SGX/SGX2: https://www.intel.com/content/www/us/en/support/articles/000058764/software/intel-security-products.html
3. Trusted Computing Group, TPM 2.0 Library Part 1: Architecture, Level 00 Revision 01.83, 25 Jan 2024: https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
4. Microsoft Learn, Get-Tpm: https://learn.microsoft.com/en-us/powershell/module/trustedplatformmodule/get-tpm
5. Microsoft Learn, TPM Command Blocking: https://learn.microsoft.com/en-us/windows/win32/tbs/command-blocking
6. OP-TEE Documentation, Secure Storage: https://optee.readthedocs.io/en/latest/architecture/secure_storage.html
7. Android Open Source Project, KeyMint functions (Rollback resistance): https://source.android.google.cn/docs/security/features/keystore/implementer-ref
8. Android Developers, Android Keystore system: https://developer.android.com/privacy-and-security/keystore
9. AWS, Security - Nitro Enclaves: https://docs.aws.amazon.com/enclaves/latest/user/security.html

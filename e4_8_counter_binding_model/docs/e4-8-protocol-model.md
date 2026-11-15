# E4.8 — TPM NV Counter 与离线预算绑定：协议模型

**阶段状态：** E4.8.1 软件模型包，待本地验收  
**范围：** 协议级并发、预算检查、回执绑定和崩溃恢复模型  
**硬件操作：** 无；本包不连接 TBS、不发送 TPM 命令、不读写真实 TPM

## 1. 本轮要回答的问题

E4.7.3 已经验证当前设备上的 TPM NV Counter 可以成功递增，并在一次正常 Windows 重启后保持精确值。E4.8 不重复这项硬件验证，而是研究：仅凭这个计数器，能否可靠地为 Agent 离线预算中的操作分配唯一消费序号，并防止克隆、并发和崩溃恢复造成的错误授权。

## 2. 规范事实

本模型依据 TCG《Trusted Platform Module 2.0 Library Part 3: Commands》Version 185（2026-03-12）：

- Table 255/256（第 356 页）：`TPM2_NV_Increment` 命令递增 NV Counter；其响应表只有 `tag`、`responseSize`、`responseCode`，不返回计数值。
- Table 265/266（第 366 页）：`TPM2_NV_Read` 是独立命令，响应参数才包含读出的 `data`。

因此，“Increment 成功”与“读到本次操作对应的唯一新序号”是两件事。两个客户端之间可以出现如下合法的命令级交错：

```text
Client A: NV_Increment  -> success
Client B: NV_Increment  -> success
Client A: NV_Read       -> 2
Client B: NV_Read       -> 2
```

这不表示 TPM 的两次 increment 没有生效；两次都生效了。问题在于 `NV_Increment` 和 `NV_Read` 是两个分离的命令，读取结果不是某次 increment 调用专属的返回值。

规范来源：

- TCG TPM 2.0 Library Part 3, Version 185, 2026-03-12: <https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf>

## 3. 模型和假设

`SimulatedNvCounter` 只建模单条 NV Counter 的命令接口：每个 `nv_increment()` 单独递增一次并仅返回成功/失败状态；`nv_read()` 单独返回当前值。模拟器对每条命令加锁，但不把 Increment 与 Read 合成一个事务。

`SerializedCounterBroker` 演示一个单一 broker 在本地锁保护下，如何把读前检查、increment、读后核验和回执分配串行化。该锁是进程内软件锁，不能抵御进程克隆、绕过 broker 的 TPM 访问或恶意本机管理员；它不是 TEE，也不是硬件互斥原语。

`Receipt` 仅用于模型展示 `lease_id`、`operation_id`、`request_digest` 与计数值之间的数据绑定。它没有密码学签名；真实实现仍需可信执行主体的签名、持久化回执和独立验签信任根。

## 4. 核心场景与预期结论

| 场景 | 模型结果 | 含义 |
|---|---|---|
| A/B 分别 Increment 后再 Read | 两者可能都读到 2 | 不能把分离的 Read 结果直接当作每个调用的唯一序号 |
| 先检查 quota 再 Increment | 并发下可能超过 quota | 仅预检查不安全 |
| Increment 后再检查 quota | 可拒绝越额执行，但可能烧掉计数额度 | fail-closed 需要接受额度损耗 |
| 单一串行 broker | 分配唯一序号 | 依赖所有 TPM 消费都必须经过这个可信单例 |
| 相同 operation_id 重放 | 返回已有回执 | 需要持久化幂等记录；本包仅模拟内存行为 |
| operation_id 被改绑到另一请求 | 拒绝 | 需要将请求摘要纳入回执绑定 |
| 崩溃后只看到 pre 与 post 值相差 1 | 在唯一未决 intent、独占恢复假设下可恢复 | 必须暂停新消费直到恢复完成 |
| 恢复期间有其他增量或差值大于 1 | 不可归因，标记 AMBIGUOUS | 不可猜测，不可自动补发预算 |

## 5. 崩溃恢复建议状态

建议未来真实实现采用 write-ahead intent：

1. 持久化 intent：`lease_id`、`operation_id`、`request_digest`、`pre_counter_value`。
2. 在唯一可信 broker 中执行 `NV_Increment`。
3. 执行独立 `NV_Read`。
4. 确认计数变化符合协议后，持久化带序号的签名 receipt。
5. 再调用外部工具，并以 `operation_id` 做幂等或状态查询。

若在第 2 步之后、receipt 持久化之前崩溃，恢复时必须暂停新消费。仅当能证明自 intent 写入以来只有这一条未决 increment，且当前计数值恰好是 `pre_counter_value + 1`，才可将其判定为本 intent 已递增并恢复回执。否则进入 `INDETERMINATE` / `AMBIGUOUS`，不能自动重试增量或执行外部工具。

外部工具效果与 TPM 计数器不属于同一原子事务。工具调用前崩溃可能造成额度损耗；工具执行后、最终回执前崩溃则可能无法判断外部效果是否发生。应要求工具支持 `operation_id` 幂等和状态查询；不支持时需要保留 `INDETERMINATE`，不能谎称 exactly-once。

## 6. 当前结论边界

目前只能得出模型级结论：

- TPM NV Counter 可提供持久化的单调数值原语（E4.7.3 已在一台设备、一次递增和一次 Windows 正常重启范围内实测）。
- 单独的 NV Counter 不会自动提供 `lease_id` / `operation_id` / 请求摘要绑定。
- 单独的 Increment+Read 两命令序列不构成一个原子“分配唯一操作序号”事务。
- 要将它用于离线预算，仍需可信串行化 broker、持久化 intent/receipt、请求绑定、恢复门禁以及外部工具幂等机制。

这些模型测试不是 TPM 并发行为的硬件实测，也不是完整 Agent 安全证明。

## 7. 本阶段验收

- [ ] `python -m unittest discover -s tests -v` 全部通过。
- [ ] 报告中明确说明模型没有连接真实 TPM。
- [ ] 不修改现有 E4.7.3 归档。
- [ ] 不运行任何 TPM 写命令。
- [ ] E4.8.1 完成后，再决定是否进入真实 TPM 只读探测或更高层的离线预算集成；不得直接跳到写硬件。

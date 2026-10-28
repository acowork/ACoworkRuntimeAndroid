# ADR-AND-002: 平台中立契约层 `acowork-platform-contract`

- **状态**：Accepted —— 已落地，248 测试通过（契约层 81 + Android 单元 101 + Android 契约 23 + Android 规则一致性 43），clippy `-D warnings` 零告警（host 与裸机 target 各自验证），`--no-default-features` 下 `no_std` 构建通过，且已在 `riscv32imc-unknown-none-elf`（无 OS、无原子指令）上编译通过
- **日期**：2026-10-29
- **相关**：[ADR-AND-001](ADR-AND-001-android-host-profiles-and-execution-backend.md)（本 ADR 改变其 §7.1 / §7.4 的**落点**、把 §4.4 的散文式权限描述**细化**为四轴，不推翻其决策）、[android-host-probe.md](../../design/zh/android-host-probe.md)、[开发就绪度评估](../../review/zh/2026-10-28-readiness-assessment.md) B1/B2/B3
- **实现**：`crates/acowork-platform-contract/`（规则）、`crates/acowork-android/src/host/`（事实与机制）、`crates/acowork-android/tests/rules_conformance.rs`（一致性证据）

---

## 1. 背景

ACowork 的目标是**多平台 node 接入**：不同平台的设备通过同一套协议挂进同一个集群。Android 是第一个端口，后面还有 ESP32 一类的嵌入式设备。这带来两个此前没有正面处理过的事实：

1. **Android 要打好样。** 第一个端口的价值不在于它自己跑通，而在于它把「什么叫符合契约」定义清楚，使第二个端口不必重新发明。如果 Android 的规则和它的机制混在一起，第二个端口就只能靠读代码猜哪些是必须照做的、哪些是 Android 特有的。
2. **要尽量减少对 `acowork` 仓库的依赖。** 就绪度评估 B3 已经指出：上游 monorepo 没有发布 tag，依赖它等于把本仓库的构建绑在一个未定版的快照上。一个将来要跑在 ESP32 上的契约，更不能拖着 `acowork-core` / `acowork-runtime` / `tokio` 一起进裸机固件。

ADR-AND-001 的 P0 切片把探测、capability 推导、门控、`avc` 回灌都放在了 `crates/acowork-android/src/host/` 里。这在只有一个平台时没有问题；一旦有第二个平台，它就是把**规则**和**Android 的事实**焊在了一起。

## 2. 决策

抽出 `acowork-platform-contract`，按一条线切分职责：

> **契约层拥有规则，平台层拥有事实与机制。**

契约层回答「任何 node 都必须满足什么」；平台层回答「这台设备实测是什么、命令怎么跑」。二者之间没有第三种东西——不存在「大部分平台都这样」的中间层，因为那种层正是第二个端口被迫继承的第一个端口的偏见。

### 2.1 为什么是契约而不是共享实现

平台之间**没有统一的执行模型**，因此不可能有统一实现：

| 设施 | Android | ESP32 一类 |
|---|---|---|
| 进程 / fork-exec | 有 | 无（单地址空间，任务即协程） |
| POSIX 文件系统 | 有 | 可能有 SPIFFS/LittleFS，无路径语义保证 |
| MMU / 地址空间隔离 | 有 | 无 |
| SELinux 域 | 有，且是真正的门槛 | 无 |
| `std` / 堆 | 有 | `no_std`，堆受限 |
| 墙钟 | 有 | 可能只有 tick 计数 |

所以本 ADR 不试图抽象出一个「通用 shell」或「通用文件系统」——那是 HAL 的工作，而且注定漏。它只固定**不变量**和**必须填的形状**：能力如何声明、声明需要什么证据、请求如何被裁决、拒绝如何被解释。

结论是：**没有统一方案，但可以有统一规则。**

### 2.2 十三条规则

规则原文与执行点在 [`crates/acowork-platform-contract/src/lib.rs`](../../../crates/acowork-platform-contract/src/lib.rs) 的 crate 文档里，是规范性的（normative）。此处只列编号与一句话，避免两处真相：

| # | 一句话 |
|---|---|
| R1 | 能力是探测事实的函数，永远不是配置的函数——没有配置文件，也没有环境变量覆盖 |
| R2 | 探测不是保证：它决定*声明*什么，逐次授权是闸门的决定 |
| R3 | node 进程自身永不持有特权；提权只存在于单次调用内部，在 `ExecutionBackend` 之后 |
| R4 | 只有真正演示过的能力才可声明；拒绝与不确定探测都不支持声明 |
| R5 | 词汇表属于协议，事实属于设备；ID 封闭且带命名空间，端口不得运行时铸造 |
| R6 | 每个能力声明同样的四轴，闸门统一合成；端口不得自创闸门逻辑 |
| R7 | 两个权威、一个合成点：*谁可以请求*归控制面（下发不透明裁决），*此刻什么可行*归设备，合取在设备上评估 |
| R8 | 不可逆操作除非调用方给出回滚路径，否则拒绝 |
| R9 | 诊断随错误一起传递且可操作：每条拒绝都指名缺失条件与下一步 |
| R10 | 请求形状属于端口；契约要的是三个答案，不是一个结构体 |
| R11 | 同一时刻只有一个变更动作，不排队、不抢占 |
| R12 | 契约不预设任何 OS 设施：无 shell、无文件路径、无进程模型、无 MMU、无 `std`、无墙钟 |
| R13 | 上报摘要不含设备标识符，也不含原始探测细节 |

**每条规则都有测试。** 规则写在文档里是意图，写成测试才是约束。契约层自己的 79 个单元测试钉住规则在契约侧的执行；Android 侧的 `tests/rules_conformance.rs`（43 个测试，命名 `r1_*` … `r13_*`）钉住 Android 满足它们。

### 2.3 依赖纪律

契约层**只依赖 `serde`**，且是 `default-features = false, features = ["alloc", "derive"]`。

- 不依赖 `acowork-core` / `acowork-runtime`（规避 B3）
- 不依赖 `async-trait` / `tokio`：异步用 `core::future::Future` + **GAT**（`type ExecuteFuture<'a>: Future<Output = ExecOutcome>`），完全不装箱。这是 `no_std + alloc` 能编译的前提，也顺带解决了一个跨平台约束问题：多线程宿主可以把它绑成 `Send` future，单线程裸机目标不必，**任何一方都不用为另一方的约束付费**（装箱的 `Pin<Box<dyn Future + Send>>` 会强迫裸机端也承担 `Send` 与堆分配）
- `std` 是一个**可关掉的 feature**，只买 `std::error::Error` 实现

已实测：`cargo tree -p acowork-platform-contract --no-default-features -e features --edges no-dev` 的输出里**没有 `serde_core feature "std"` 边**。（注意必须带 `--edges no-dev`：dev-dependency `serde_json` 会拉进 std，那是测试用的，不进 lib 依赖图。）

**并且已在真裸机 target 上编译通过**：

```
cargo build  -p acowork-platform-contract --no-default-features --target riscv32imc-unknown-none-elf   # OK
cargo clippy -p acowork-platform-contract --no-default-features --target riscv32imc-unknown-none-elf -- -D warnings   # 零告警
```

`riscv32imc-unknown-none-elf` 是 32 位 RISC-V、无操作系统、**且无 `a` 扩展（没有原子指令）**。选它不是因为手边正好有：它是能拿到的最严格的 R12 检验——比 ESP32-C3 的 `riscv32imac`（有原子）还少一项设施。cfg 的两个分支因此都被覆盖：host（有原子）跑 9 个锁测试，裸机（无原子）不带锁也能编译。

### 2.4 分层职责

| 关注点 | 契约层 | Android 层 |
|---|---|---|
| 能力四轴（effect / approval / reversibility / attribution） | `CapabilitySpec` 类型与合成规则 | 五个 `android:*` ID 的**取值** |
| 探测纪律（有界、一次、事件失效） | `ProbeBudget` / `Evidence` / `audit_claims` | 探测**哪些命令**、如何解析输出 |
| 授权闸门 | `Gate::decide`（纯函数，无平台分支） | 提供 `GateView` 的事实来源 |
| 归属裁决 | `AttributionVerdict`（不透明布尔，无身份） | 从 Gateway 取回并投递 |
| 本地就绪 | `LocalReadiness` 三开关的**语义** | 三开关的**取值**（dangerous-mode / 锁 / 审批） |
| 资源锁 | `ResourceLock` 语义（TTL、不排队、不抢占）、`LockState` | `SessionWriteLock`：带 session 身份的实现 |
| 执行 | `ExecutionBackend` trait、`ExecOutput`（字节）、`ExitStatus`（无 signal 变体） | `ExecRequest`（含 `cwd` / `env`）、`su -c` 包装、超时 |
| 诊断 | `DiagnosticClassifier` trait、`Remedy`、`RepeatLedger` | `avc: denied` 解析、SELinux 域分类 |
| 宿主描述 | `HostDescription` trait、`HostSummary`（五字段）、`PrivilegeLevel` | `HostProfile` 实现该 trait |

判据是一句话：**换一个平台，左列一行都不用改，右列全部重写。**

## 3. 一致性测试就是「打样」的交付物

`crates/acowork-android/tests/rules_conformance.rs` 不是普通的测试文件，它是**第二个端口的模板**。文件头写明了用法：

> 新平台复制这个文件，保留规则名，替换 fixture。某条规则在该平台不适用时，测试要**显式说明**，而不是被悄悄删掉——让「缺席」成为一个有记录的决定。

这条约定是有意的。ESP32 上 R8（回滚路径）可能整体不适用，因为没有可回滚的持久状态；但如果只是把测试删了，后来人无法区分「这个平台不需要」和「这个平台忘了做」。

失败时的读法也写在文件头：**`rN_*` 测试失败不是「测试坏了」**，它意味着端口不再满足整份多平台设计所依赖的某条规则，修复属于端口或契约，**不属于断言**。

本轮已经验证过这个机制有效——见 §5。

## 4. 对 ADR-AND-001 的影响

不推翻任何决策，但改变两处的**落点**，并新增一处**细化**：

| ADR-AND-001 | 关系 | 原落点 | 现落点 |
|---|---|---|---|
| §7.1 「Gateway 不做门控判定」 | 落点迁移 | `host/backend.rs` | 契约 `gate.rs`：Gateway 做*归属*判定，不做*能力*判定；合取在 `Gate::decide` |
| §7.4 两权威合成 | 落点迁移 | `host/backend.rs` 的 `authorize` | 契约 `gate::Gate::decide`（R7 的执行点） |
| §4.4 五件套的「默认」列 | **细化** | 散文式描述（「需审批」「白名单自动放行」）+ §4.6 的可逆性护栏 | 契约的四轴 `CapabilitySpec`：effect / approval / reversibility / attribution |

关于第三行要说清楚：**四轴模型是契约层新引入的，ADR-AND-001 里没有这张表。** §4.4 只有「覆盖范围 / 默认」两列，可逆性散落在 §4.6 的护栏条目里，归属门控在 §7.4。把它们收敛成每个能力都必须声明的四个正交轴，是为了让 R6 成立——闸门统一合成四轴，端口就不能自创闸门逻辑。五个 `android:*` ID 的**取值**仍然由 Android 层决定（`Capability::spec()`），契约只提供轴的类型与合成规则。

就绪度评估 B1 的「两权威 + 单一合成点」解法**内容不变**，只是从 Android 层上移到了契约层——这恰好是它该有的位置：B1 的冲突源于上游两份文档在回答不同的问题，而「不同的问题」是平台无关的。

被删除的 Android 层类型（已上移到契约）：`AttributionVerdict`、`AuthorizationContext`、`LocalReadiness`、`Denial`、`Grant`、`authorize`、`DeviceWriteLock`、`LockOutcome`、`CapabilitySet`、`DenialHint`。

> **一处需要澄清的命名巧合**：测试里出现的 `android:kernel:write` **不是**词汇表成员，它在任何文档里都不存在。它是一个「格式合法但未注册」的 ID，专门用来证明 R5 的查找是封闭的（`r5_an_id_outside_the_vocabulary_is_refused_not_defaulted`）。词汇表就是 §4.4 的五个，由 `r5_the_android_vocabulary_is_exactly_the_five_adr_ids` 逐个钉住。

## 5. 后果

### 5.1 已验证的收益

一致性测试在写完后立刻抓到一个**契约层的真缺陷**：八条 `Refusal` 里只有 `AttributionDenied` 的文案只说了条件、没给下一步（「控制面没有为本会话授权 `Manage` 档」——然后呢？）。这违反 R9。

更能说明问题的是它**为什么一直没被发现**：契约层自己的单元测试 `refusal_messages_name_the_rule_and_the_remedy` 抽查了 index 3/4/6/7 的补救语，**恰好跳过了 index 5**。Android 侧的测试更严（要求每条都指名主语），才把它暴露出来。

修复落在源头（契约的 `Display` 实现），并在**两处**都补了断言。新文案明确了设备侧无法自行放宽归属裁决，因此重新探测设备是白费——这正是 R9 要防止的那类无效往返。

### 5.2 裸机编译抓到的三个可移植性缺陷

R12 此前只用「特征图里没有 std 边 + `#![no_std]` 能编译」间接验证过。真正拿裸机 target 编一次，立刻暴露两个间接验证**永远看不到**的问题——它们都不是 std 问题，而是宽度和指令集问题：

**缺陷一：`ResourceLock` 用了 `AtomicU64`。**

32 位 target 上没有 64 位原子。ESP32-C3 是 `riscv32imac`，同样 32 位，**同样没有 `AtomicU64`**——也就是说这个缺陷会在点名的第二个平台上直接编译失败。改用 `AtomicUsize`。

**缺陷二（由修复一引出）：`usize` 会回绕，而原来的时间算术是 saturating 的。**

32 位下毫秒计数器每 ~49.7 天回绕一次。原代码用 `saturating_sub` 算持有时长：一旦持锁跨越回绕点，`now < held_since`，saturating 减法返回 **0**——持有 10 分钟的锁会被读成「刚拿到 0 毫秒」，进而被判定为**未过期**还是**已过期**取决于比较方向，任一方向都错：前者永久楔住设备，后者放第二个写者进来。改为 wrapping 减法（嵌入式处理 tick 溢出的标准手法，即序列号算术）：只要 elapsed 远小于回绕周期就正确，而 TTL 是分钟级，差四个数量级。

**缺陷三（由修复二引出）：`+1` 哨兵与回绕相互抵消。**

锁用 `0` 表示「未持有」，因此存入的是 `now_ms + 1`。改成 wrapping 之后，`now_ms == usize::MAX` 这一个输入会**正好别名到哨兵 `0`**——锁存成「未持有」，下一个调用方直接走进来。这就是 R11 唯一要防的事。在 32 位目标上，这个毫秒每 49.7 天出现一次。

修法是把这一个输入映射到可表示的最大持有值：它读回来比真值早 1 毫秒（无害），而读成 `FREE` 会放进第二个写者（R11 禁止）。**失效方向被刻意选成「保持锁定」，永远不是「打开」。**

三个缺陷都补了回归测试（`acquisition_at_the_counter_maximum_still_locks`、`elapsed_time_survives_a_counter_wrap`）。注意第二、三个是在修第一个的过程中被推理出来的——如果只把 `AtomicU64` 换成 `AtomicUsize` 就收工，会留下一个每月失效一次、且失效方式是**静默允许并发写**的锁。

**还有一项限制被显式记录而非糊过去**：`riscv32imc` 连原子指令都没有（`max_atomic_width = 0`），CAS 无从表达。`ResourceLock` 因此按 `target_has_atomic = "ptr"` 条件编译。这**不使 R11 变成可选**：无原子的目标实践上是单核协作式调度，互斥要么平凡、要么属于端口已有的临界区。规则归契约，那一种无锁编码只是参考机制。

### 5.3 成本

- **多一个 crate**：workspace 从 1 个变 2 个，构建图多一层。相对于「第二个端口要读 6000 行代码猜规则」，这个成本很低。
- **类型转换税**：Android 的 `Privilege` 要映射到契约的 `PrivilegeLevel`，`HostProfile` 要实现 `HostDescription`。这是显式的适配代码，不是隐藏耦合。
- **契约层不能随便改**：它一旦有第二个消费者，改签名就是跨平台破坏性变更。这是**特性**不是缺陷，但意味着契约层的改动要比平台层更谨慎。

### 5.4 风险与未决

| 风险 | 缓解 |
|---|---|
| 契约层只有一个消费者（Android），抽象可能是错的 | R6 的 `the_gate_has_no_platform_branch` 测试用一个虚构的 `esp32` 能力表驱动同一份闸门代码，证明闸门里没有平台分支。但**真正的检验是第二个端口**，在此之前契约应视为可修订 |
| 契约层将来该放哪 | 目前在本仓库。若上游接受 B2 的注册表提案，词汇表所有权会上移，但 R1–R13 的规则本身与注册表是两件事（见 §2.2 R5 与契约 lib.rs 的「What this crate is not」） |
| 无原子的 target 拿不到 `ResourceLock` | 已按 `target_has_atomic = "ptr"` 条件编译并在契约 lib.rs 与类型文档里写明：R11 的**语义**仍是强制的，端口自带机制（单核协作式目标上是临界区）。这不是待办，是一个已记录的边界 |
| 裸机验证用的是 `imc` 而非 ESP32 实际的 `imac` | `riscv32imac-unknown-none-elf` 与 `riscv32imac-esp-espidf` 的 rust-std 组件下载被网络策略阻断（连接超时），只能退到已安装的 `imc`。`imc` 比 `imac` **少一项设施**（无原子），所以它是更严格的检验；但 ESP-IDF 的 `std`/分配器行为仍未实测。**在真 ESP32 上跑一次之前，R12 算「在最严格的可用 target 上验证过」，不算「在目标平台上验证过」** |

## 6. 备选方案

| 方案 | 为什么不选 |
|---|---|
| **不抽层**，第二个端口复制 Android 代码再删 | 复制的是 6000 行里混着的规则和机制，删的时候无法判断哪行是规则。等于让每个端口重新做一遍本次拆分 |
| 抽一个**共享实现**（通用 shell/fs 抽象） | §2.1：平台间没有统一执行模型，这种抽象必然漏，而且漏在嵌入式端 |
| 契约层依赖 `acowork-core` 复用其 `Permission` | 违反 B3（上游无 tag）；且 `Permission` 是封闭 enum（B2），词汇表所有权未定，绑上去等于替上游做了决定 |
| 用 `async-trait` 写异步 trait | 它把返回类型装箱成 `Pin<Box<dyn Future + Send>>`，既假定 `std` 又强制 `Send`——裸机端要为此付出堆分配和一个它根本用不上的约束。改用 GAT 关联 future 类型后两者都不需要，R12 成立 |
| 规则只写文档，不写测试 | 文档里的规则是意图。§5.1 那个缺陷就是证据：文案规则写在 R9 里，但没有测试逐条覆盖时，一条漏了没人知道 |

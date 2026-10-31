# 开发就绪度评估 —— ADR-AND-001 与上游的一致性核对

- **日期**：2026-10-28
- **范围**：[README.zh.md](../../../README.zh.md)、[ADR-AND-001](../../adr/zh/ADR-AND-001-android-host-profiles-and-execution-backend.md)、[ADR-AND-002](../../adr/zh/ADR-AND-002-platform-contract-layer.md)（2026-10-29 新增）、[android-host-probe.md](../../design/zh/android-host-probe.md)
- **核对基准**：上游 `AgentCowork` @ `0b5e8f14`（2026-10-28）
- **结论**：**文档质量高，但有 3 条硬阻塞（B1/B2/B3）需上游裁定。** P0 只读切片不被阻塞，已交付并通过验收判据。
  > **已提交上游评审（2026-10-29）**：B1 + B2 已整理成请求裁定文档，提交至 `AgentCowork/docs/review/zh/37-android-write-tier-attribution-and-capability-registry-review.md`（2026-11-02 补：该文件此前只存在于工作树、从未进入上游版本控制，现已提交为上游 `e1cc9aab`，未 push）（B1 含三个必答问题 Q1 执行点 / Q2 契约归属 / Q3 无主节点；B2 给出 a/b/c/d 四个选项，推荐 a「新增 Node/设备安全域表」）。**等待裁定，未获结论前 P3 生产接线不落地。**
  > **B3 的影响面已收窄，但未消除。** 规则层抽成只依赖 `serde` 的独立 crate 后，「引擎归属形态二义」无论上游怎么裁定都**不波及规则层**，且这是结构保证（裸机 target 编译 + lib 依赖图无 std 边）而非约定。但 B3 二义的本来就是*引擎*（node + runtime）的归属，README 路线图 #2 的引擎抽取**仍然阻塞**——契约层解决的是宿主规则，不是引擎归属。
  > **三条阻塞的当前形状**：B1 解法已在契约层落地为规则 R7 并有三个测试钉住，**等的是上游对 §7.1 字面修订的确认**（Q1/Q2/Q3）；B2 **无解法可落地**——它缺的是一张上游表，本地领域类型 + 待建适配层只能把改动面积压到一个文件，不能替代裁定；B3 只阻塞引擎抽取，不阻塞 Android 移植。

---

## 1. 评估方法

不评价文档「写得好不好」，只核对文档**声称的上游事实是否成立**。ADR-AND-001 引用了 6 处上游契约，逐条实测：

| ADR 的声称 | 实测结果 |
|---|---|
| 「沿用上游 `filesystem:read:<path>` 粒度风格」新增 capability | ⚠️ 上游 `Permission` 是**封闭 enum**，见 B2 |
| 「与 Gateway 的协议契约不变」（N4） | ❌ 不成立，见 B2 |
| 「复用上游 `shell.rs` 双 shell 注册范式」 | ⚠️ 范式存在，但命名不一致，见 B5 |
| 「与 ADR-087 owner 门控叠加」（§7.4） | ❌ 逻辑上不能同时成立，见 B1 |
| 「Gateway 不做门控判定」（§7.1） | ❌ 被上游两份文档推翻，见 B1/B2 |
| 「上游 `12-tool-system.md` 已定义平台检测流程」 | ✅ 成立，但矩阵需改，见 B5 |

**关键时间线事实**：ADR-AND-001 提交于 2026-10-20；上游 design 30 v0.2 提交于 2026-10-24；上游 ADR-087 v3 修订于 2026-10-28。**两份推翻它的文档都比它晚。** 而 ADR 正文标注的日期是 `2026-05-15`，却引用了 2026-09-13 才创建的 ADR-075、2026-10-05 的 ADR-087、2026-10-09 的 ADR-090 —— 该日期不可能成立（见 B7）。

---

## 2. 硬阻塞（需上游或产品裁定）

### B1 —— §7.4 归属门控与上游 ADR-087 D5 逻辑上不能同时成立

| 来源 | 裁定 |
|---|---|
| ADR-AND-001 §7.4 | 放行 = 设备本地 `dangerous-mode` ∧ **请求者是 node owner** |
| ADR-AND-001 §7.1 | Gateway 只做展示筛选，**不做门控判定**；放行始终在设备本地 |
| 上游 ADR-087 D5 | 执行点 = **Gateway 反代入口**，「Runtime 不引入 owner 概念（它拿不到也不该拿归属真相）」 |
| 上游 ADR-087 D1 | owner 只存 Gateway 侧 `node_owners.json`，**不进 MQTT proto，Node 不感知用户** |
| 上游 ADR-087 §129 | 显式否决「owner 进 proto 由 Node 上报/回显」：「鉴权根基不能建立在可被更低信任级组件覆写的通道上」 |

设备本地拿不到 owner 真相，就无法评估 §7.4 的第二个合取项；而 §7.1 又禁止 Gateway 判。两条路都堵死。

**叠加风险**：ADR-087 自身仍是**草案**（§12 有开放问题），且 v3 修订晚于本 ADR 提交。

**影响面**：P3（写档）整阶段。**P0/P1/P2 只读档不受影响。**

#### 已采用的解法：两权威 + 单一合成点

这不是折中，是分解——两份文档在回答不同的问题：

| 问题 | 权威 | 为什么在那里 |
|---|---|---|
| **谁**可以请求写档动作？ | Gateway → `AttributionVerdict` | ADR-087 D1/D5：owner 真相在 `node_owners.json`，在反代入口执行。设备不能也不该重建它 |
| 这台设备上**什么可行**、此刻**是否安全**？ | 设备 → `HostProfile` + `dangerous-mode` + `DeviceWriteLock` | 只有设备知道探测事实、本地会话开关、以及是否有别的 session 正在写 |

设备收到的是**不透明布尔裁决**，不含 user id / owner 名 / 角色。这既满足 ADR-087「Node 不感知用户」（布尔量不是用户），又保留 ADR-AND-001「最终合取在设备评估」（探测事实在设备）。两个权威互不重复，因此不存在第二处会漂移的真相。

**这确实修订了 §7.1 的字面表述**：Gateway 做*归属*判定，不做*能力*判定。

**上游已有的先例支持这个形状（2026-10-29 复核 ADR-087 全文后补）**：D8 已裁定「`GET /api/nodes` 每条记录服务端算好 `can_manage` / `can_use` **布尔**下发，Desktop/Mobile **只消费布尔渲染，不再自行推导**」。`AttributionVerdict` 不是新发明，而是同一纪律用到设备侧消费者上——服务端判定、布尔下发、客户端不推导。这一先例显著降低了本请求的说服成本。

**D7 对本解法的约束**：D7 裁定无主资源 fail-closed、只有 admin 可 manage。当前实现把「无裁决」一律拒绝，比 D7 更严——D7 隐含 admin 可以另路授权。已在提交文档中作为开放问题（Q3）请上游裁定 admin 裁决在设备侧的形状。

> **落点已迁移（2026-10-29，[ADR-AND-002](../../adr/zh/ADR-AND-002-platform-contract-layer.md) §4）**：原写在 [backend.rs](../../../crates/acowork-android/src/host/backend.rs) 的 `AttributionVerdict` / `AuthorizationContext` / `authorize` 已上移到契约层 [gate.rs](../../../crates/acowork-platform-contract/src/gate.rs)，成为 `AttributionVerdict` / `LocalReadiness` / `Gate::decide`，即规则 **R7** 的执行点。
> 迁移的理由与本节的分析同源：B1 的冲突源于上游两份文档在回答**不同的问题**（谁能请求 vs 此刻什么可行），而「不同的问题」是平台无关的——把它留在 Android 层，第二个端口就得自己再推导一遍同样的分解。
> 解法内容**未变**，并由 `r7_the_conjunction_happens_on_the_device_and_neither_authority_suffices`、`r7_the_attribution_verdict_carries_no_identity`、`r7_a_verdict_cannot_be_replayed_against_a_higher_tier` 三个测试钉住。

### B2 —— capability 词汇表所有权已被上游收走，N4「协议契约不变」不成立

实测事实：

1. 上游 `Permission`（`core/acowork-core/src/permission.rs`）是**封闭 enum**，带 `PermissionTag` 数字映射（proto）、`from_str`、`to_string`、`implies()`、`category()`、`type_name()`、`type_value()`、`wasi_mapper` 共 7 处 match。新增一个 capability = 改上游 core + proto，**不是本仓库的本地改动**。
2. 上游 design 30 v0.2 §6.2 三条裁定：**「新增能力的唯一路径是注册表 PR，不存在运行时自定义能力通道」**、「引擎不能自造能力 ID 上 UI」、**「能力是布尔开关，不带参数」**。
3. 而 `android:fs:outside-app`（写 `/data` 下非自身路径）本质是**带路径参数**的能力，`android:shell:read` 的白名单命令集也是参数 → 与「布尔开关」冲突。
4. 命名空间不一致：design 30 用点分（`fs.read` / `shell.exec`），本 ADR 用冒号（`android:shell:read`）。
5. design 30 §9 已点名：「其 HostProfile 能力上报（§7.1）**应改为**同一份能力注册表（§6.2）的一个来源」。

#### 复核后的修正（2026-10-29）：不是「布尔 vs 带参」，是**上游有两张表，都没有它的位置**

上面第 3、4 条把冲突写得太粗。逐字复核上游代码与文档后，事实是：

| 上游表 | 位置 | 命名 | 形状 | 语义 |
|---|---|---|---|---|
| 引擎能力注册表 | design 30 §6.2 / D12 | 点分 | **布尔，不带参数**，参数化走 §6.3.2 schema | 引擎*能配置什么* |
| `Permission` | `permission.rs:112` | **冒号 + 参数** | `FilesystemWrite(Option<String>)`、`Network(Option<String>)`、`IntentSend(Option<String>)` | **agent** manifest 被授权的范围 |

所以「上游能力是布尔开关」只对第一张表成立：已发布的 `Permission` enum **本身就带路径参数、本身就是冒号命名**。真正的缺口不是形状不符，而是**归属**：

- 「可写路径前缀」不是**用户可设置项**——D14 明文「参数 schema 只描述用户可设置项，不接管生效值来源」。用户若能把它调宽，等于让 UI 扩权，所以它不能进 §6.3.2 的参数 schema。
- 它也不属于 `Permission`——那张表的所有者是 **agent manifest**，而 HostProfile 上报的主体是 **Node**（本 ADR §7.1 已裁定「能力归 Node」，与 ADR-075/ADR-090 同向）。
- 布尔注册表只装得下「执行档」这类事实（`android.shell.root` 可以拆成布尔），装不下命令集与路径前缀。

**三处都塞不进去**，这才是需要上游裁定的东西——而且它顺带暴露了上游自身的命名不一致（design 30 点分 vs `Permission` 冒号），不是本 ADR 单方面的问题。

#### 已采用的解法：本地领域类型 + 待建的薄适配层

探测出的事实是**本地领域模型**；wire 词汇表是**外部契约**。二者本就该分层。

- [capability.rs](../../../crates/acowork-android/src/host/capability.rs) 定义本仓库自己的 `Capability`，**不依赖** `acowork_core::Permission`。
- 序列化走契约 ID（`android:shell:read`）而非 Rust 变体名，因此变体重命名不会改变 wire 形态。
- 词汇表封闭：`parse_capability` 对未知 ID 返回 `None` 而非默认值——静默接受未识别的 capability 正是词汇表变更升级为提权的路径。
- 映射到最终注册表的适配层**暂不实现**。裁定无论倒向哪边，成本是一个文件，不是重写探测。

### B3 —— 引擎归属形态在上游自身就是二义的

- README 前提：独立仓库 + `crates/acowork-android` 共享引擎 + 「干净的上游回流路径」。
- design 30 §5 方案表：A（源码级上游化，编进 `acowork-runtime`）判定为「**仅用于自有引擎（Android）**」。
- design 30 §9：ADR-AND-001 的「D0 引擎归属在 D 方案下消解为**依赖已发布 Host crate**」。

Android 到底是「编进上游 runtime 的 crate」还是「依赖已发布 Host crate 的独立引擎」？这决定仓库结构、CI、发布节奏。且后者依赖的 `acowork-runtime-protocol` / `acowork-engine-interface` 两个契约 crate **目前都不存在**（design 30 S1/S2 才交付）。design 30 §9.1 已实测确认本仓库对上游的依赖痛点（无 tag、无发布、path 依赖、103MB 仓库）但尚未解。

**时序风险（判断，非事实）**：design 30 §1.1 明确「这条 roadmap 的架构权重**高于** Android 高权限 runtime」，S2 又是「风险最高的一步」。现在按「共享引擎 crate」开工，S2 落地后大概率返工。

#### 已采用的解法：本 crate 零依赖引擎

design 30 §9 自己说「`ExecutionBackend` 在**引擎内部**，EIP 在**引擎外部**」，二者正交。因此本 crate 只依赖 `serde` + `async-trait`，**不依赖** `acowork-runtime` / `acowork-core`。这使它在方案 A 与方案 D 下**同时成立**：既可折进上游作为模块，也可作为独立 crate 被消费。B3 的二义性因此不必在 P0 之前解决。

> **已进一步加强（2026-10-29，[ADR-AND-002](../../adr/zh/ADR-AND-002-platform-contract-layer.md) §2.3）**：规则层被抽成独立 crate `acowork-platform-contract`，依赖**只有 `serde`**——连 `async-trait` 也去掉了，异步改用 `core::future::Future` + GAT 关联 future 类型（不装箱）。
> 这不是洁癖：`async-trait` 会把返回类型装箱成 `Pin<Box<dyn Future + Send>>`，既假定 `std` 又强制 `Send`，裸机端要为此付出堆分配和一个它用不上的约束。去掉它之后契约层能在 `riscv32imc-unknown-none-elf`（无 OS、无原子指令）上编译通过。
> 对 B3 的影响：原来「零依赖引擎」是**约定**（靠 code review 维持），现在是**结构保证**——`cargo tree --edges no-dev` 的 lib 依赖图里没有 `serde_core feature "std"` 边，且裸机 target 编译是硬门。B3 的二义性因此不仅不必在 P0 前解决，**无论上游怎么裁定都不会波及规则层**。

---

## 3. 中等阻塞（事实补全，不涉争议）

### B4 —— APK 交付物与上游 `apps/acowork-mobile` 形态撞车，文档零交叉引用

上游**已有** Android APK：`apps/acowork-mobile`（Tauri v2，`Cargo.toml` 含 `cfg(target_os = "android")` + `jni`），对应 design 25 v1.3「工程开发中」+ ADR-086。

定位**相反**：

| | 上游 acowork-mobile | 本仓库 acowork-android-app |
|---|---|---|
| 定位 | 「IM 形态的对话控制终端」 | 「常在线、可被 Gateway 访问的 Agent 宿主」 |
| 本地 Gateway | ❌ 明确无 | 需承载 Node Agent |
| Agent 管理 | ❌ v1 不做 | 核心职责 |
| 依赖 | 刻意不带 `acowork-core` / `rumqttc` | 需完整 Node + Runtime |

在三份文档里 grep `acowork-mobile|ADR-086|Tauri|25-mobile`：**零命中**。

未回答的产品问题：用户装两个 APK？还是 mobile 长出 host mode？包名 / 签名 / 前台服务 / 电池白名单如何共存？

**附带浪费**：上游 mobile 已跑通 Android NDK + Tauri 构建管线，而 README 写「构建：目前尚无可构建内容……待补充确切的 NDK 版本与目标三元组」——已有事实未被复用。

### B5 —— 上游平台矩阵与工具命名未对齐

- 上游 `12-tool-system.md` §2.1：`shell` 在 Android = ❌，级别「**仅桌面端**」。本 ADR 要 termux / root-shell 两档都 ✅。上游矩阵必须改，ADR 未提。
- 命名：上游 `shell.rs` 源码注释（第 3-5 行）的实际范式是——Windows 注册 `bash` + `powershell` 两个工具，**Linux/macOS 注册单个名为 `shell` 的工具**。probe §5.1 说「沿用上游双注册范式：`bash`（Termux）、`ash`」，但 Termux 是 Linux 语义，上游在 Linux 上并不叫 `bash`。

### B6 —— Node spawn 契约硬编码兄弟二进制名

上游 `core/acowork-node/src/process/spawn.rs:110-130` 硬编码 `current_exe().parent().join("acowork-runtime")`；design 30 §1.3 称之为「最硬的耦合点」。本仓库 CLI 叫 `acowork-android`，且 README 说同时移植 Node + Runtime 两层——ADR / README 都未说该契约如何处理（改名？配置化？等 design 30 的 `package kind = engine`？）。

### B7 —— 文档元数据与约定

- ADR 与 probe 均标**日期 2026-05-15**，但引用了 ADR-075（上游 2026-09-13 创建）、ADR-087（10-05）、ADR-090（10-09）。日期不可能成立 ⇒ 无法判断 ADR 相对上游 churn 的新旧，而这正是 B1/B2 的关键。
- ADR 状态标「Accepted（遗留问题已全部裁定）」，但 §7.1 已被 design 30（10-24）要求改写，§7.4 与 ADR-087（10-28）矛盾。
- 上游 `AGENTS.md:142`：「每个中文 ADR 都有英文对应件，且必须**同一 commit** 更新」。本 ADR 写「EN mirror：待补」，`docs/design` 也只有 zh。若声称「干净的上游回流路径」，这条约定迟早要还。
- probe 状态 **Draft**，但 ADR §6 的 P0 阶段直接以它为验收依据。

---

## 4. 实现期新发现的契约缺口

以下 5 条是在写 P0 代码时暴露的，纯读文档看不出来。

### B8 —— probe §3 的 `shell` 单值字段无法表达 ADR §4.5 的双工具注册

ADR §4.5 要求注册 `bash` 与 `ash` **两个独立工具**，但 §3 契约只有 `shell: Option<ShellDialect>` 一个值。已在 `HostProfile` 增加 `dialects: BTreeSet<ShellDialect>`，`shell` 保留为「主方言」。**需回写 probe §3。**

### B9 —— 宿主档优先级未定义

两份文档都没说档位如何判定。已裁定优先级 `RootShell > Termux > SystemShell > ApkSandbox`，其中**「有没有 shell 真的执行」决定 shell 档与 ApkSandbox 的分界**，`bash` / `$PREFIX` 是否存在决定 Termux 与 SystemShell 的分界。

理由：以 `$PREFIX` 为判据会把 `adb shell` 宿主（uid 2000、mksh、无 Termux、无 su）误判为 ApkSandbox，同时仍从探测到的 shell 推出 `android:shell:read`——得到一个自相矛盾的 profile。以「shell 是否真的执行」为判据后，不变量变成结构性的：**ApkSandbox ⟺ 未声明 shell 能力**，`assemble` 里用 `debug_assert_eq!` 钉住，并在 `host_profile_contract.rs` 里以 release 模式跨各档复验。

**SystemShell 是后加的第四档**，来自真机对账：BLA-AL00（user 版、无 Termux、无 root）此前落进 `Termux`，于是 `HostSummary.profile` 对上游声称了一个装 Termux 的环境，而探测项 5a 与 13 都没观察到它。判据换成「probed `bash` 或 `$PREFIX` 存在」之后，这台设备落在 `system-shell`，能力结论不变（`shell:read` 有、`shell:write` 无），变的是它不再声称自己没见过的东西。

### B10 —— probe §4 与 §3 自相矛盾：observed-denials 存哪

§4 要求把 denial「累计到 HostProfile 的 observed-denials」，§3 又声明 profile「一次生成，会话期内只读」。二者不能同时成立。

已裁定：denial 累计放在**独立的会话级** `DenialLedger`。这同时满足 ADR §7.1——observed-denial 明细永不上报 Gateway，而把它排除在被上报的 profile 之外，使这一点成为**结构性保证**而非「记得过滤」。

### B11 —— `android:shell:write` 是否也需要 ADR-087 归属门控（开放）

ADR §7.4 只裁定了 `fs:system` 与 `selinux:permissive` 两条需要 owner 门控，代码严格照此实现。但 ADR-087 D4 把「安装 / 卸载」归入 `manage = owner ∨ admin`，而 `android:shell:write` 覆盖 `pm install`。

已把映射暴露为**数据**而非埋进门控：`Capability::attribution_tier()` 返回 `None / Use / Manage`，当前 `ShellWrite → Manage` 是**临时**标注，门控并不消费它。这样 B11 的答案只需改一个 match 分支，且临时映射是可见、可测的，而不是隐式的。

### B12 —— probe §3 的 `fs:system` 推导规则漏了 shell 前置条件

§3 写的是 `verity != Enforcing 且 /system 实测可 remount`。但 remount 意味着**执行 `mount` 命令**，无 shell 的宿主无论如何做不到——这正是 ADR §7.3 陈述为事实的那句话（「APK 档根本没有 shell，也没有 su，`android:fs:system` 在 APK 上不可达」）。

缺这个前置条件会让 APK 档声明一个它无法行使的能力，即 design 30 §11.1 警告的「能力谎报」——比「没有能力」更伤信任。已为 `fs:system` 与 `selinux:permissive` 补上 shell 前置条件，`explain_gaps` 同步给出对应理由。**需回写 probe §3。**

---

## 5. 已交付：P0 切片

对应 ADR §6 的 P0（`ExecutionBackend` trait + HostProfile Probe），验收判据「单元测试用伪造 probe 输出」已满足。

| 层 | 文件 | 职责 | 纯度 |
|---|---|---|---|
| 数据模型 | [facts.rs](../../../crates/acowork-android/src/host/facts.rs) | 每个探测事实一个类型 + 一个文本解析器 | 纯函数，无 I/O |
| 采集契约 | [probe.rs](../../../crates/acowork-android/src/host/probe.rs) | 12 项探测命令、预算、结果路由 | 契约 + 路由 |
| 聚合 | [profile.rs](../../../crates/acowork-android/src/host/profile.rs) | 装配为会话内只读的 `HostProfile` | 纯函数 |
| 推导 | [capability.rs](../../../crates/acowork-android/src/host/capability.rs) | capability 是事实的函数，不是配置项 | 纯函数 |
| 执行契约 | [backend.rs](../../../crates/acowork-android/src/host/backend.rs) | `ExecutionBackend` + 合成两权威的门控 | 纯门控 + async trait |
| 回灌 | [denial.rs](../../../crates/acowork-android/src/host/denial.rs) | `avc: denied` → 可执行的下一步 | 纯函数 + 会话账本 |

**质量门**：`cargo test` 115 通过（98 单元 + 17 契约）；`cargo clippy --all-targets -- -D warnings` 零告警；`cargo fmt --check` 干净。工具链对齐上游：edition 2024 / rust-version 1.95 / `async-trait` 0.1.92。

**契约测试**（[host_profile_contract.rs](../../../crates/acowork-android/tests/host_profile_contract.rs)）覆盖 probe §7 要求的两项：

- 档位快照基线（现为四档，见 B9）：user 版 `adb shell`、user 版 + Termux、userdebug + Magisk root、APK 沙箱
- 真机地面实况：`tests/fixtures/devices/huawei-bla-al00-api29.json` 是一台 BLA-AL00 的逐字回包，`tests/device_ground_truth.rs` 用它逐字段对账 —— 上面那些快照是**我们以为设备会给出的值**，这一份是**设备实际给出的值**，两者不一致时以后者为准（首次对账就发现三处不一致）
- 四项故障注入：su 弹窗被拒、`getenforce` 不存在、toybox/busybox 双缺失、`/system` remount 失败 —— 均降级而非 panic
- 外加 ADR §6 P1 的不变量：root-shell 档下 Runtime 自身 privilege 恒 `< Root`
- 外加 ADR §7.1 红线：Gateway 摘要在每一档上均不泄漏 SELinux context / fs_roots 路径 / ABI / build type

### 测试发现的 13 个真实缺陷

先写测试的价值——以下都不是测试写错，是实现或设计错：

| # | 缺陷 | 后果（若未发现） |
|---|---|---|
| 1 | applet 列表不处理 busybox 的逗号分隔输出 | 裸 `busybox` 的 applet 全部丢失，工具描述谎报「命令不存在」 |
| 2 | `PathOutsideRoots` 在可提权宿主上抢先触发 | **对 root 档说「路径不对、提权也没用」——把模型从唯一可行的修复上引开** |
| 3 | `fs:system` 无 shell 也能推导（B12） | APK 档声明无法行使的能力，即「能力谎报」 |
| 4 | 档位优先级允许「ApkSandbox 却声明 shell 能力」（B9） | profile 自相矛盾，工具注册与档位判定打架 |
| 5 | `Capability` 按 Rust 变体名序列化 | 变体重命名会静默改变 wire 形态与快照基线 |
| 6 | `AttributionRefused` 消息只说原因不给下一步 | 违反 N3；策略拒绝退化为重试循环 |
| 7 | 路径判定跑在**字面拼写**上，不解析 `..` | `/data/local/tmp/../../../dev/block/mmcblk0` 判成普通文件写：§4.6.3 的硬禁加三段路径即可绕开；反向也错——`/data/local/tmp/../../system` 其实是 `/data/system`，多要一次没人做坏事的审批 |
| 8 | 写目标由**设备**决定时仍按字面前缀判定（`$VAR`、glob、`~`） | `echo x > $TARGET` 花最轻的写档，落点由运行时变量决定；`rm -fr *` 相对一个没人能看见的工作目录删东西 |
| 9 | `sed -i` 只识别「发生了就地编辑」，不看编辑**哪个**文件 | `sed -i 's/a/b/' /system/build.prop` 只要 `fs:outside-app` 就改到分区 |
| 10 | `cp`/`mv`/`ln` 把第一个操作数当作被写的文件——那其实是**源** | `cp /data/local/tmp/x /system/bin/y` 花最轻的写档改分区；`mv ... /dev/block/mmcblk0` 不判禁 |
| 11 | 目的地藏在 flag 里（`cp -t DIR x`），操作数列表只剩源 | 「最后一个操作数是目的地」会把改分区的请求读成写临时文件；`-t` 支持与否是没量过的事实，而拒绝不该等测量 |
| 12a | `dd` 只认第一个 `of=` | 脚本里写了两个目的地，审批只看见轻的那个 |
| 12 | 重定向**顶掉**命令自身的写效果 | `sed -i 's/a/b/' /system/build.prop > /data/local/tmp/log` 只按重定向定档，就地改写分区那一半从审批里消失 |
| 13 | `key=value` / `--flag=value` / 粘连短 flag 里的路径对路径谓词**不可见** | `dd if=/dev/block/mmcblk0`、`grep --file=/proc/1/environ` 判只读免审批——token 不以分隔符开头，三个前缀谓词全部落空；真机验证 `dd if=<文件> of=<文件>` 真的在拷（"4 bytes copied"），是可用路径不是拼写 |
| 14 | 只认「输出目的地」这一个 flag | `sort -T /system/tmp` 判只读（真机验证 toybox 接受 `-T`，临时文件就写在那儿）；`sort --compress=PROG` 是**第二条命令**，NESTED 表只看命令词所以看不见 |
| 15 | 命令词之外的执行面没有规则 | `dumpsys SurfaceFlinger --screenshot FILE` 判只读，而 `screencap FILE` 判写——同一个文件两套答案。本机实测该 flag 被忽略（三种拼写都不落文件），规则是为会写的那版建的 |
| 16 | **读**侧隐私名单是五个家的穷举 | `/data/anr` 在名单外且真机可读（`drwxrwx--x system`，里面一个 root 属 0666 的 trace，`head -c 24` 直接读出别的进程的栈）；名单改成「`/data` 减去本 uid 唯一的 `/data/local/tmp`」 |
| 17 | 携带敏感内容的操作数**不是路径** | `content query --uri content://sms/` 在本机以 uid 2000 跑出真实短信正文、`content://contacts/people` 跑出真实联系人姓名，分类器答 ReadOnly、§4.4 免审批并记成「读」。前面 16 条规则全都建立在「操作数长得像路径」上，URI 不是路径 |
| 18 | 用户自己的文件与别的 app 的文件混用一条规则 | `/sdcard`、`/sdcard/DCIM` 以 uid 2000 可列（实测），相册免审批；而 `cp 报告 /sdcard/报告` 是 `fs:outside-app` 这个名字承诺过的写——所以媒体树只进**读**侧名单，且命令自己已定档的目的地不再被当作一次读 |
| 19 | harness 先跑探针、后跑命令 | §14 每一行都打印 NO-SUCH-FILE，无论设备做了什么——`sort -o` 因此只能靠人手在手机上量，地面实况段落在自己手里变成假测量 |
| 20 | 端口自己生成的脚本被端口自己的门拒绝 | 包存在性探针写成 `pm path X \| grep -q .`，`.` 是相对路径 → 分类器拒绝 → 每个 `pm install` 的 undo 前置状态都是「未观测」，而那条 undo 是存在的 |

7–12a 是同一个错误的七个面：**分类器把「脚本里出现了一个路径」当成「我知道文件会落到哪」**。源不是目的地，写法不是落点，而设备在内核里替它解析的东西（`..`、变量展开、glob、家目录）端口若不自已解析，就是在让请求的措辞决定它被允许要求什么。四条都是先把断言写出来、看它失败才成立的——读代码只会同意它，不会推翻它。

13–18 是同一个错误的另一面：**把「有一个路径操作数」当成「我知道在读谁的数据」**。前一条的病在写侧，这一条的病在读侧，而读侧更贵——§4.4 免审批，所以错的分类不会变成一次拒绝，只会变成一条写着「read」的日志。17 尤其要记住：它连路径都不是，所以任何按前缀写的规则都不可能命中它。19–20 是同一个纪律的反向用法——测量装置和被测量的门，两者都得被人怀疑一次才可信。

缺陷 2 值得单独记：`fs_roots` 探测的是**非特权**可达范围（probe §2 item 12 只探 `$PREFIX` / `/sdcard` / 自身包目录），**不是** root 可达范围的穷举（README 矩阵写的是「`/data` 大范围」）。因此「路径在 fs_roots 之外」只在**无法提权**的宿主上才等价于「路径错了」。修正后该分支以 `can_escalate` 为前置守卫。

---

## 6. 建议的下一步

> **2026-10-29 更新**：本表原列的两项本仓库动作已完成，另新增契约层相关两项。已完成项保留在表内并标注，便于核对。

| 优先级 | 动作 | 归属 | 状态 |
|---|---|---|---|
| P0 | 把 B1 的「两权威」方案与 B2 的注册表提案提交上游评审 | 需上游 | ✅ 已提交（2026-10-29）——`AgentCowork/docs/review/zh/37-android-write-tier-attribution-and-capability-registry-review.md`，B1 含三个必答问题 Q1 执行点 / Q2 契约归属 / Q3 无主节点，B2 给出 a/b/c/d 四个选项；B1 方案在契约层已落地为 R7，文档直接附 `r7_*` 测试作为可执行说明。**状态：等待裁定** |
| P0 | 修正 ADR 日期、把 §7.1/§7.4 标注为待对齐 | 本仓库 | ✅ 已完成 |
| P1 | 与 mobile app 负责人对齐 B4 的 APK 形态归属 | 需产品 | ⬜ 未开始 |
| P1 | 回写 probe §3（B8 `dialects`、B12 shell 前置条件）与 §4（B10 ledger） | 本仓库 | ✅ 已完成（2026-10-29） |
| — | 抽出平台中立契约层，使规则不绑在 Android 上（规避 B3、为第二个端口打样） | 本仓库 | ✅ 已完成 —— [ADR-AND-002](../../adr/zh/ADR-AND-002-platform-contract-layer.md)，完成时 476 测试（现 565） |
| — | 在真实嵌入式 target 上验证 R12（ESP32-C3 `riscv32imac-unknown-none-elf` 或 `riscv32imac-esp-espidf`） | 本仓库 | ⚠️ 部分 —— 已在更严格的 `riscv32imc`（无原子）上编译通过；`imac` 与 ESP-IDF 的 rust-std 组件下载被网络策略阻断 |
| P2 | 实现只读档 backend（`ShellBackend` / `RootShellBackend` / `AppSandboxBackend`）+ adb 传输层 + 真机 harness | 本仓库，不被阻塞 | ✅ 已完成（2026-10-30）—— 20 条只读探测（原 18，后加 13 / 13b 两项证据面探测）+ `assemble` + 真实命令在 BLA-AL00 上跑通，~120ms / exit 0 / uid 2000。**getprop 与 mount 已实测**；`logcat` / `dumpsys` 此前是**手工**实测可读、不属于探测集——现已由探测项 6c 收进集合（真机 10 项抽查中 8 项不在任何 `--list` 输出里，含 §4.4 点名却谁都看不见的 `settings`） |
| P2 | §4.4 只读白名单按**脚本内容**判定（自称 read 的写命令在执行前被拒），§4.6.3 硬禁列表任何档位拒绝 | 本仓库，不被阻塞 | ✅ 已完成（2026-10-31）—— [`host/commands.rs`](../../../crates/acowork-android/src/host/commands.rs)，29 个新测试；BLA-AL00 实测 `settings put` 挂 read 标签被拒并指名 `android:shell:write`，`toybox rm -rf` 设备根在任何档位被拒 |
| P2 | 只读档的动态工具描述（§4.5：按探测结果生成 `bash` / `ash` 两个工具的描述文本） | 本仓库，不被阻塞 | ✅ 已完成（2026-10-31）—— [`host/tools.rs`](../../../crates/acowork-android/src/host/tools.rs)，13 个新测试；BLA-AL00 实测生成一条 `ash` 描述，七项只读命令全部在内（其中 `getprop` `dumpsys` `logcat` 只因探测项 6c 去抽查才可见） |
| P3 | §4.6.4 写操作可撤销：捕获前态 → 生成逆操作 → 会话结束按 LIFO 恢复 | 本仓库，不被阻塞 | ✅ 已完成（2026-11-01）—— [`host/rollback.rs`](../../../crates/acowork-android/src/host/rollback.rs)，20 个新测试 + `ReversibleBackend` 装饰器；BLA-AL00 实测三条前态（`setprop` 空串→近似逆操作、`settings put` `1.0`→精确逆操作、`setenforce` `Enforcing`→`setenforce 1`），并且**真写了**：第 10 节连写两次 `debug.acowork.probe` → 恢复 → 回到原值（LIFO 在硬件上才显出必要：按记录顺序会停在中间值并报成功），被 SELinux 拒掉的 `persist.sys.*` 写没留下任何 undo。顺带发现并补上一处地板：后端此前不查「这台设备是否声明过该能力」，harness 直接驱动 `ShellBackend` 时 `setprop` 真的跑了（闸门会拒，但闸门是纯函数），现在 `check_declared` 在派生之前拒，审计新增 `undeclared` 分类。文件快照（2026-11-01 补上）：exec 通道按 `from_utf8_lossy` 解码，经它读文件不等于读文件，所以快照走 base64、主机侧不解码、账本只存路径与 digest；`/system/bin/printf` 实测 100 KiB 参数可达、128 KiB 报 `Argument list too long`，故分片（48 KiB/片）；不用 heredoc——分类器会把载荷每行读成命令，改用命令通道需要重写一个安全关键组件的引号词法；设备上有 `sha256sum`，回写末步比对写前 digest，丢片因此是报出来的失败而不是悄悄短了的备份。捕获分两次读取（先 `wc -c` 决定要不要继续，4 GB 文件只花一次 `wc`），超 64 KiB 预算照样执行并在收尾点名，只建模干净绝对路径。真机第 11 节：含 NUL/0xFF 的 5 字节文件创建→覆盖→LIFO 恢复；61440 字节随机文件被 9 字节覆盖、两片回写后 digest 一致；65537 字节被拒。**`am`/`pm`/`input` 已逐条分类**（2026-11-01）：`UnundoableKind` 把「本端口还没建模」与「设备上没有原语」与「它根本不是状态改动」分开——此前一句文案盖住三种事实，收尾日志因此整体失去可信度。三条量出来的事实决定了形状：这台设备的 `pm help` 没有 `install-existing`（故 `pm uninstall` 是 `NoRestorableState` 而非可商量的缺口）；`pm list packages -d` 返回 0 行而 `-e` 返回 300 行且把三种禁用态折成一个列表（故 `pm disable` 的「现成逆操作」不能确认恢复的是同一种态，标 `NotModelled` 并写明原因）；`pm set-install-location` 落的是 `global/install_location` 而非 secure（栈证据 `insertGlobalSetting`），且 shell uid 2000 被 `SecurityException` 拒、exit 255——顺带真机验证了「失败的写不建 undo」（账本 0 条，是正确行为）。建模两条：`pm set-install-location` 复用 Setting 路径、`pm install --pkg NAME` 用 `pm path` 存在性信封（缺失→`pm uninstall`，已存在→无逆操作）。**装卸的真机 round-trip 未做**，且是有意的：验证它需要往这台手机装东西，而没跑过的 undo 正是这本账最不该作的承诺 |
| P3 | 写档（依赖 B1 裁定） | 阻塞中 | ⬜ 阻塞中——但阻塞点只剩审批归属（B1）：「没有撤销路径」这条技术前置已随上一行关闭，能力表里的「Reversible」从断言变成了有所指 |

**已经做完并接着做了下一步**：P1 只读档的 backend 实现、`SpawnRunner` 平台接缝、adb 传输层与真机 harness。它们不触及 owner 门控（B1 只影响写档）、不触及 Gateway 契约（只读命令本地放行）、不依赖引擎归属（B3 已被零依赖设计规避，且现在是结构保证而非约定）。

**真机对账换来的东西比功能本身多**：把 17 条探测在设备上跑一遍、与 fixture 逐字段比对，暴露出五个问题——
`sh --version` 在真机上直接报错、`attr/current` 以 NUL 结尾、"有 shell"被当成"shell 执行过"、无 Termux
时注入 `$PREFIX`、无 Termux 的设备被标成 `termux` 档。五条已全部修掉并在真机上复验：前两条在解析层，
第三条是判据，后两条是档位模型在编造事实。

值得记下来的是，这五条同时存在时整套测试是 **316 个全绿**的。其中四条只有真机能推翻——伪造 fixture
只能证明解析器与自己自洽，证明不了它对上了任何一台设备；第五条（注入 `$PREFIX`）是写后端时读代码
发现的。

**还欠着的**（除命名一条外，都需要设备或上游）：

一台设备都不在手的时段里，本表新增的行会显式写出「仅单元验证」，而不是把 harness 的旧结论
当作本轮的结论：伪造的 fixture 只能证明解析器与自己自洽，证明不了它对上了任何一台设备；
设备重新接上之后，这些行要按 harness 重跑一遍才算数。

| 缺口 | 现状 | 需要什么 |
|---|---|---|
| `su` 拒绝措辞 | `parse_su_probe` 认 `denied` / `permission denied` / `not allowed` / `rejected` / `cancelled` 五种，全部是推断；`su_prompt_denied` 与 `su_helper_missing` 的分类表同理 | 一台装了 Magisk / KernelSU 的设备，实测弹窗拒绝与 helper 缺失各自的 stderr |
| `ShellPaths.su` | **已补**：新增探测项 4a（`command -v su`），`assemble()` 从此填充 `paths.su`。此前该项恒为 `None`，而 `RootShellBackend` 没有它就不肯构造——root 档只能从手写 profile 到达。本机实测 4a 与固定路径探测一致（exit 1、空输出，`PATH` 上六个目录都没有） | 仍需在**有 root 的设备**上对比两种解析：固定路径清单没有覆盖 `/vendor/xbin`、`/debug_ramdisk` 之外的位置，而 `command -v` 会 |
| 孤儿进程 | **已修复**：spawn 时 `process_group(0)` 让子进程自成一组，超时先 `kill(-pgid, SIGKILL)` 再补直接子进程。改前先测过——`sleep 30 &` 的孙进程在原实现下确实活满了剩下的 29 秒。`kill_process_group` 里那两条守卫（pgid ≤1 拒绝、已被 reap 的 pid 拒绝）是它存在的全部理由：`0` 会打到我们自己那组，`-1` 会打到本 uid 能达到的每个进程，而回收后的 pid 会打死一个陌生人。范围只在超时路径：正常结束却留下后台任务的脚本仍然会孤儿化，那是 Unix 的 `nohup`/`setsid` 语义，不是缺陷 | 无 |
| 审计日志 sink | **已实现**（`host/audit.rs`，§4.6.1）：`AuditedBackend` 装饰器 + `AuditSink` trait + 限长 JSONL 文件实现。开口记录写不进就拒绝执行（fail closed），收尾记录写不进只累计失败计数（命令已经跑了，谎报失败会诱导重试一次已发生的改动）。拒绝也记账，且带 `RefusalKind`——硬禁尝试与贴错档位是两类事件 | 节点侧决定落盘目录与保留策略 |
| SELinux context 经错误文案上线 | **已修复**：`BackendError::to_contract()` 把 `observed_context` 原串拼进过线文案，违反 §7.1；当时的单测还断言着这个泄漏。改为只报 uid + 域的类别（六值固定词表），原串留在本地 `ExecRecord`/`Display`。新增遍历全部错误变体的守门测试 | 无 |
| SELinux 拒绝明细经**命令输出**上线 | **已修复**（§7.1 的第三个出口，也是最大的一个）：`ExecRecord::to_contract()` 原样搬运 stdout/stderr。avc 审计记录是内核写进 audit log 的，所以它到达本进程的方式不是「后端出错」而是 §4.6 item 6 第一条取证命令的输出——BLA-AL00 实测一次 `logcat -d -b events -t 400` 带 181 条记录（175 denied + 6 granted）、181 处 `u:r:`、234 处 `u:object_r:`、23 处 `s0:c` 与第三方应用私有目录路径，全部过线。现在投影处重写审计记录：保留权限集 / 对象类 / 目标类型（平台 sepolicy 词表），丢掉 user / role / MLS 区间 / 路径；非记录行逐字节不动（`ps -Z` 保留）。**守门测试当时结构上不可能发现**：断言写在 `serde_json::to_string(&outcome)` 上，而 `ExecOutput.bytes` 是 `Vec<u8>`，序列化成数字数组，任何内容都能通过 | 无 |
| 证据源能不能采集 | **已实现两半**：探测项 13 / 13b 逐源实测「在不在 / 能不能列 / 几条 / 能不能读」，`dumpsys -l` 数服务清单；采集动作由 [`host/evidence.rs`](../../../crates/acowork-android/src/host/evidence.rs) 落地（2026-11-01，harness 第 12 节真机）。原结论「无 root 时六个源没有一个能取到内容」**是说过头了**——它量的是文件源，说的却是六个源。分开之后：四个取得到（`screencap -p` 1 377 361 字节 PNG / 6 次读、`logcat -d -t 400` 46 346 字节、`dumpsys <service>` 逐服务、`bugreportz` 4 101 144 字节 zip / 1m44s 生成 + 16 次读），两个取不到（`/data/anr`、`/data/tombstones`：列目录能过、开文件被拒，设备原话 `Permission denied`）。产物以 base64 过桥（exec 通道 `from_utf8_lossy`，经它读二进制不等于读它），按 256 KiB 分片（读方向的上限是 1 MiB 输出上限，不是写方向的 printf 参数上限），并用**设备传输前自算的 sha256** 验收：丢片即 `DigestMismatch`，不留半个 PNG。§4.5 的工具描述按实测访问级逐源点名，`not probed` 也占位 | 有 root 的设备上重测那两个文件源（预期 `readable`）；`dumpsys` 的逐服务可达性仍要一台台问；关联分析（产物交给分析步骤）未做 |
| `dumpsys` / `logcat` | 在同一设备上手工实测：shell uid 在 user 版上 `logcat -d` **读到的是全量缓冲区**（拿到了别的进程的日志行），`dumpsys -l` 能列服务。**「它们不属于探测集」这句已作废**——探测项 6c 已把两者收进集合，且实测证明必须收：二者都不是 toybox applet，批量列表看不见它们。仍未验证的是单个 service 的转储（`dumpsys package` 等）；若要作为工具开放，需按工具而非按档位来记 | 逐项 service 验证 |
| `dumpsys` 单个服务不存在时 | **已修复（2026-11-01，仅单元验证）**：设备对不存在的服务是 **exit 0 + stdout 就是 `Can't find service: <name>`**——拒绝的内容就是全部输出。采集器原先只看退出码，于是这行会被分片取回、写成一个几百字节的"成功"artifact，调用方只有打开文件才知道被骗。现在转储前先 `head -c 128` 看一眼 artifact 自己的开头（这是唯一能抓住它的时刻，因为拒绝不是错误码而是输出本身），命中就返回新错误变体 `CaptureError::DeviceRefused`，一个字节都不搬、目录都不建。哨兵字符串不是新发明：`parse_dumpsys_inventory` 早就拒绝把这一行解析成服务清单，两处现在共用同一个形状。**只匹配实测过的那一条**——猜别的措辞会造出一个放过真拒绝的过滤器，而放过的代价是谎报成功。**同时刻意没上**的是 `dumpsys -t <secs> <service>`：给服务自己的工作量上限在原理上是对的（主机超时只停止我们等，不停止手机继续产出），但 `-t` 的参数顺序是 AOSP 知识而非本机实测，而 EMUI 的 dumpsys 是改过的——猜错的后果不是"没省下"，而是把今天能用的采集搞坏。尺寸风险改用可验证的方式兜住：超预算的转储在搬第一个字节之前就被拒。| 需要设备：把 `-t` 的参数顺序实测出来，并跑 harness 第 3b 节（`battery` 成功 / `powermem` 拒绝）确认这两条在硬件上成立 |
| 符号链接写目标 | **词法别名已修复（2026-11-01，仅单元验证）**：分类器的每条路径判定原先都是前缀匹配，`/data/local/tmp/../../../dev/block/mmcblk0` 因此被判成普通文件写（应为硬禁），`.../../../../system/x` 同理（应为系统写）——硬禁能加三段路径绕开就不叫硬禁。现在统一走 `script::resolve_path`，分类器与回滚规划器共用（规划器原先自己判 `/dev/` 前缀，会同意去 `base64` 一个裸块设备并把 `rm -f` 设备节点写进账本）。反向也钉住：`/data/local/tmp/../../system` 解析成 `/data/system`，不是分区，误判会让调用方为没做的事审批。**剩下的正是解析解决不了的**：`/data/local/tmp/link -> /system/bin/sh` 字面上无害、落点在读分区，而这一层看不见文件系统——`test -L` 要为每个被分类的词多一次设备往返，`O_NOFOLLOW` 对交给 `/system/bin/sh` 的脚本不可用 | 需要设备与策略决策：要么接受「每次分类多一次 `readlink` 往返」的成本，要么把写目标限制到探测已确认可写的根之下（后者是策略收紧，需上游归属裁定 B1 之后才不至于自造第二套权威） |
| 相对路径写目标 | **已修复（2026-11-01，仅单元验证）**：分类器原先把不以 `/` 开头的目标当已知路径，而 `resolve_path` 把 `./f` 读成 `/f`——只有工作目录正好是 `/` 时才成立。于是 `echo x > ./f` 拿到 `fs:outside-app`，而设备坐在哪个目录是审批里没有人知道的事实（cwd 若为 `/system`，这就是一个系统写）。现在非绝对路径一律 Destination::Unknown → Opaque，`rm x`（裸名）也顺带从 FileWrite 变成拒批。配套修的是操作数角色：`chmod 755 /system/bin/x` 的 `755`、`touch -t 202401010000 f` 的时间戳都不是路径，新增 `looks_like_path`（含分隔符或以 `.`/`/` 开头才算）把它们挡在目标表外——否则"相对即未知"会把它们误判成目的地、把整条命令拖成 Opaque | 无（纯词法事实，已单元钉住；真机侧没有需要测的措辞） |
| 分区根表不全 | **已修复（2026-11-01，仅单元验证）**：`SYSTEM_ROOTS` 原先是从 `/system`、`/vendor` 的读数长出来的，缺 `/persist`（华为设备上的 modem 校准）、`/odm`、`/dsp`、`/mnt/vendor`。后果是 `printf %s x >> /persist/f` 只要 `fs:outside-app`，而删 `/persist` 下的内容不在硬禁之内——校准数据删掉是不可恢复的设备改动，与删 `/system` 同档。现补入表中，`rm` 的硬禁随之覆盖 | 需要设备：确认这些挂载点在本机真实存在及其权限（分类器的判定不依赖这个结果，缺挂载点时写自然失败） |
| app 私有数据目录 | **已修复（2026-11-01，仅单元验证）**：`/data/data/<pkg>`、`/data/user/<n>/<pkg>`、`/data/user_de/<n>/<pkg>` 下的写原先也只要 `fs:outside-app`——而这个能力的名字承诺的正是"写在 app 数据之外"。本端口词表里还没有 app-data 档（即上游评审 B2），所以先归到较重的一档 `fs:system`：代价是可能多要一次审批，反向的代价是给了一个没人请求的权限。`/data/local/tmp`（shell 自己的暂存）不受影响，`/data/database.txt` 这种"名字像但不是子路径"的也不受影响 | 需要 B1/B2 裁定：app-data 是否应成为独立档，以及由谁下发 |
| 一条命令里的多个重定向 | **已修复（2026-11-02，仅单元验证）**：`cmd > a > b` 原先直接拒绝，理由是"端口不建模哪个文件赢"——那句话本身是错的：POSIX 下两条重定向都生效，`a` 被截断、stdout 进 `b`，所以是两个文件都改。现在分类器取全部重定向目标的最重档并在文案里点名每一个；planner 相应改成**每个目标一笔快照**（`Command.outputs` 与 `ParsedCommand.redirects` 都成列表），顺带修掉两个连带的洞：① `setprop a b > /data/log` 这类"属性写 + 重定向"原先只快照属性，日志文件凭空出现且无人记账；② 目标里有一个不可快照（glob/相对/`$`）时，原先因为"最重档相等"而不触发任何点名——账本因此看着完整、其实少一笔，这条现在按目标逐个报 `IndeterminateTarget`。测试是先写失败的、被自己抓住的（`a_command_that_redirects_into_two_files_snapshots_both`） | 无（词法与 POSIX 语义，已单元钉住）；harness 已加第 14 节（多重定向的实际落点、`-t` 是否被本机 shell 实现、相对目标落在哪个 cwd），但本机现在没有连接设备，**该节尚未跑过** |
| `-t DIR` 与 `install` | **已修复（2026-11-02，仅单元验证）**：这两类原先都报 Opaque——理由写的是"要不要认 `-t` 取决于本机 toybox 是否实现它，而没测过"。理由站不住：目的地就写在明文两个 token 之外，`mv -t /system x` 报"说不清"不是保守，是不肯说自己看得见的事。现在 `flag_destination` 读 `-t`/`--target-directory`（分开与粘连两种拼法）并按该目录定档，`mv` 仍同时计入被搬走的源（rename 会把它们从原目录 unlink）；`install` 进 FILE_WRITE，按 cp 取最后操作数，`install -d` 按 mkdir 取全部操作数。看不见仍是看不见：`cp -t ./system/bin x`、`mv -t $DEST x`、`install -d ./x` 一律 Opaque（读 flag 不等于猜 flag）。`touch -t` 不受影响——那条规则是给"用同一串字母装时间戳"的命令留的 | 需要设备：第 14 节量这三件事——`command -v install` 的有无、`mv -t DIR` 是否真把目的地搬进去、`cmd > a > b` 是否两个文件都被打开。分类结果不依赖这个答案（设备忽略 `-t` 时写会失败或落到别处，不会变成一次没人被通知的写），但**规则描述的是不是这台手机的 shell**，只有跑过才知道 |
| 元数据写的档位不一致 | **已修复（2026-11-02，仅单元验证）**：`chcon`/`restorecon`/`setcontext` 原先落在"改设备状态"这一类（`android:shell:write`），而同一个 inode 上的 `chmod 777 /system/bin/sh` 却要 `fs:system`——档位差在动词拼写，不在设备上发生了什么。改标签是对那个文件的元数据写，现按文件所在分区定档（安全上下文参数不当作路径读，否则会凭空多出一笔写；`restorecon` 后面没有可命名路径时照旧拒批）。顺带补了 `unlink`：它原先不在任何写表里，`unlink /system/x` 报 Opaque，而它删的就是给定的那个名字 | 无（档位一致性是端口自己的纪律）；`chcon` 在本机的实际权限需设备验证（SELinux 可能直接拒绝，拒的代价是写失败，不是没人通知的写） |
| 账本只备份重定向的目标 | **已修复（2026-11-02，仅单元验证）**：命令自己改的文件原先一律不快照——`sed -i 's/a/b/' /system/build.prop`、`cp a /system/b`、`rm -f /data/local/tmp/x` 都只被"点名"为 unundoable，而 ADR 承诺的是"改文件先备份"。快照机制（envelope 读 + 分片回写 + digest 校验）早就存在，缺的只是"这条命令改哪些文件"这个问题的答案。现在分类器直接回答它（`file_writes` → 路径 + `Content`/`Metadata`/`Deletion`），规划器逐文件建快照，且用的是同一套操作数角色判定，不留第二份实现。删除也建快照（内容能在写之前读出来），但 inode/owner/mtime 回不来，按既有机制标 `faithful: false`；元数据改动**不**建内容快照并说明理由——恢复一个根本没变过的东西等于谎报。顺带修掉同类硬编码 `logcat -f`（原先不看路径一律 FileWrite），并把"审批重于任何可恢复文件"留作安全网。附带发现并修掉一个更早的洞：`rm -f /data/x > /data/log` 这类"删除 + 可快照重定向"里，删除那一笔原先因为档位相等而不触发任何点名 | 需要设备：`/system` 下的文件恢复要 `fs:system` 才跑得动，只有 root 档拿得到；shell 档下这类 undo 会进 `failed` 并如实报告，这条路径需要真机确认措辞 |
| 读侧名单上会写文件的命令 | **已修复（2026-11-01，仅单元验证）**：`sort`、`sed`、`date` 都在只读名单上，因为它们通常是过滤器——但 `sort -o FILE` 写文件，`sed '/x/w FILE'` 也写文件，而 `date -s`/`date 010100002026` 设的是全局时钟。三条原先一律答 `ReadOnly`（免审批自动放行），root 档下等于无人同意就往 `/system` 落一个文件。现在 `sort -o`/`--output` 按目标路径定档（`flag_value` 认 `-o FILE`、`-oFILE`、`--output=FILE` 三种拼法，因为三种在这台 shell 上都成立；只认分开那种就是给 `sort -o/system/x` 答"过滤器"）；`file_writes` 同步认 `-o`，账本因此对 `sort -o /system/x f` 快照 `/system/x` 而不是什么都不记；`sed` 的 `w`/`r` 走 Opaque——端口不解析 sed 程序，猜文件名就是"审批上写着 `/data/local/tmp/x`、实际写进 `/system/y`"那个反复出现的失败形状，判据用分隔符计数把 `s/a/w/`（替换成字母 w）留在放行侧；`date` 的设钟形态归 `ShellWrite`（设备全局、没有任何快照能覆盖时钟）。分类器的不变量测试加了这三条形状，账本加了"目的地藏在 flag 里也要逐目标快照"与"分类器拒定位时账本必须明说无从恢复"两条 | 需要设备：harness 第 14 节第 6 项实测 `sort -o`、粘连 `-oFILE`、`sed 'w FILE'` 是否真在这台 shell 上写出文件，以及 `date -s` 缺操作数时的报错措辞（第 14 节刻意**不**执行设钟——把时钟拨回去没有恢复手段，TLS、包缓存和全盘时间戳都会受影响，只探"这个 flag 存不存在"） |
| 读侧名单还漏了两类东西 | **已修复（2026-11-02，仅单元验证）**：上一轮把「读别人的 app 数据」抬到 `ForeignRead`，但规则只认私有根表，于是 `cat /dev/block/mmcblk0` 与 `cat /proc/1234/environ` 仍然判 `ReadOnly`（§4.4 免审批自动放行）。前者是**整块分区**——写它早在 §4.6.3 硬禁名单上，读它却什么都不花，而这一个参数就能读出所有应用的数据；后者是别的进程的地址空间与启动参数（token 常在其中）。两条都归同一个档：要审批、不改状态、账本不建快照（`changes_state()` 已经是假，所以不需要新逻辑）。判据刻意是词法的：端口不可能为一次分类多跑一趟 `stat /proc/<pid>` 去问这个 pid 属于谁，所以「数字目录名或 pid 通配 + 敏感条目名（environ/mem/smaps/smaps_rollup/pagemap/maps/cmdline/fd）」即算，`/proc/self`、`/proc/thread-self`、`/proc/meminfo` 明确留在读档。**边界由端口自己的用法钉住**：事实探测读的是 `/proc/*/attr/current`（SELinux 上下文），它不在敏感表里，因此这条规则没有烧掉端口自己的诊断能力；而 `cat /proc/*/cmdline` 从免审批名单里移出去了——通配所有 pid 读启动参数正是这条规则要问的动作，端口不依赖它。同轮还扫完只读名单上「参数对了就会写」的命令：`uniq INPUT [OUTPUT]` 的第二个操作数是输出文件（POSIX 与 toybox 都这样），已按落点定档并进 `file_writes`；`strings -o 5` 是偏移不是目的地（钉住 `ReadOnly`）；`base64` 在 toybox/busybox/coreutils 里都没有输出 flag，保持过滤器 | 需要设备：harness 第 14 节第 5 项现在多列 `/proc/1/environ`、`/proc/self/environ` 与 `/dev/block`，量的是「这条规则在这台机器上到底保护了够得着的东西吗」——shell 档读 `/proc/1/environ` 大概率是 `EACCES`，那不等于规则没价值，而是它只在 root 档上才成为漏洞；这条判断需要真机读数才能写进结论 |
| 第四档命名 | `system-shell` 描述的是"无 Termux 的普通 shell"，与 adb 无关（adb 只是这次到达它的方式） | 若上游摘要要按档位做调度，命名需与上游对齐 |

**新增的一条**：`crates/acowork-android/tests/rules_conformance.rs` 是第二个端口的**模板**，不是普通测试文件。任何新平台接入时应复制它、保留 `r1_*`…`r13_*` 命名、替换 fixture；某条规则在该平台不适用时要显式说明而非删除。详见 ADR-AND-002 §3。

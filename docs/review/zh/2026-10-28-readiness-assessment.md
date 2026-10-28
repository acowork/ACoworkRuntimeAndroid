# 开发就绪度评估 —— ADR-AND-001 与上游的一致性核对

- **日期**：2026-10-28
- **范围**：[README.zh.md](../../../README.zh.md)、[ADR-AND-001](../../adr/zh/ADR-AND-001-android-host-profiles-and-execution-backend.md)、[android-host-probe.md](../../design/zh/android-host-probe.md)
- **核对基准**：上游 `AgentCowork` @ `0b5e8f14`（2026-10-28）
- **结论**：**文档质量高，但有 3 条硬阻塞（B1/B2/B3）需上游裁定。** P0 只读切片不被阻塞，已交付并通过验收判据。

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

**这确实修订了 §7.1 的字面表述**：Gateway 做*归属*判定，不做*能力*判定。落点：[backend.rs](../../../crates/acowork-android/src/host/backend.rs) 的 `AttributionVerdict` / `AuthorizationContext` / `authorize`。

### B2 —— capability 词汇表所有权已被上游收走，N4「协议契约不变」不成立

实测事实：

1. 上游 `Permission`（`core/acowork-core/src/permission.rs`）是**封闭 enum**，带 `PermissionTag` 数字映射（proto）、`from_str`、`to_string`、`implies()`、`category()`、`type_name()`、`type_value()`、`wasi_mapper` 共 7 处 match。新增一个 capability = 改上游 core + proto，**不是本仓库的本地改动**。
2. 上游 design 30 v0.2 §6.2 三条裁定：**「新增能力的唯一路径是注册表 PR，不存在运行时自定义能力通道」**、「引擎不能自造能力 ID 上 UI」、**「能力是布尔开关，不带参数」**。
3. 而 `android:fs:outside-app`（写 `/data` 下非自身路径）本质是**带路径参数**的能力，`android:shell:read` 的白名单命令集也是参数 → 与「布尔开关」冲突。
4. 命名空间不一致：design 30 用点分（`fs.read` / `shell.exec`），本 ADR 用冒号（`android:shell:read`）。
5. design 30 §9 已点名：「其 HostProfile 能力上报（§7.1）**应改为**同一份能力注册表（§6.2）的一个来源」。

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

两份文档都没说三档如何判定。已裁定优先级 `RootShell > Termux > ApkSandbox`，且**分界线是「是否有 shell 真的执行成功」**而非「`PREFIX` 是否存在」。

理由：以 `$PREFIX` 为判据会把 `adb shell` 宿主（uid 2000、mksh、无 Termux、无 su）误判为 ApkSandbox，同时仍从探测到的 shell 推出 `android:shell:read`——得到一个自相矛盾的 profile。以「shell 是否真的执行」为判据后，不变量变成结构性的：**ApkSandbox ⟺ 未声明 shell 能力**，`assemble` 里用 `debug_assert_eq!` 钉住，并在 `host_profile_contract.rs` 里以 release 模式跨三档复验。

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

- 三档快照基线：user 版 + Termux、userdebug + Magisk root、APK 沙箱
- 四项故障注入：su 弹窗被拒、`getenforce` 不存在、toybox/busybox 双缺失、`/system` remount 失败 —— 均降级而非 panic
- 外加 ADR §6 P1 的不变量：root-shell 档下 Runtime 自身 privilege 恒 `< Root`
- 外加 ADR §7.1 红线：Gateway 摘要在三档上均不泄漏 SELinux context / fs_roots 路径 / ABI / build type

### 测试发现的 6 个真实缺陷

先写测试的价值——以下都不是测试写错，是实现或设计错：

| # | 缺陷 | 后果（若未发现） |
|---|---|---|
| 1 | applet 列表不处理 busybox 的逗号分隔输出 | 裸 `busybox` 的 applet 全部丢失，工具描述谎报「命令不存在」 |
| 2 | `PathOutsideRoots` 在可提权宿主上抢先触发 | **对 root 档说「路径不对、提权也没用」——把模型从唯一可行的修复上引开** |
| 3 | `fs:system` 无 shell 也能推导（B12） | APK 档声明无法行使的能力，即「能力谎报」 |
| 4 | 档位优先级允许「ApkSandbox 却声明 shell 能力」（B9） | profile 自相矛盾，工具注册与档位判定打架 |
| 5 | `Capability` 按 Rust 变体名序列化 | 变体重命名会静默改变 wire 形态与快照基线 |
| 6 | `AttributionRefused` 消息只说原因不给下一步 | 违反 N3；策略拒绝退化为重试循环 |

缺陷 2 值得单独记：`fs_roots` 探测的是**非特权**可达范围（probe §2 item 12 只探 `$PREFIX` / `/sdcard` / 自身包目录），**不是** root 可达范围的穷举（README 矩阵写的是「`/data` 大范围」）。因此「路径在 fs_roots 之外」只在**无法提权**的宿主上才等价于「路径错了」。修正后该分支以 `can_escalate` 为前置守卫。

---

## 6. 建议的下一步

| 优先级 | 动作 | 归属 |
|---|---|---|
| P0 | 把 B1 的「两权威」方案与 B2 的注册表提案提交上游评审 | 需上游 |
| P0 | 修正 ADR 日期、把 §7.1/§7.4 标注为待对齐 | 本仓库 |
| P1 | 与 mobile app 负责人对齐 B4 的 APK 形态归属 | 需产品 |
| P1 | 回写 probe §3（B8 `dialects`、B12 shell 前置条件）与 §4（B10 ledger） | 本仓库 |
| P2 | 实现 `TermuxBackend` + `RootShellBackend`（P1 只读档），真机跑通 getprop / dumpsys / logcat | 本仓库，不被阻塞 |
| P2 | 补 B5 的上游平台矩阵改动、B6 的 spawn 契约方案 | 需上游 |
| P3 | 写档（依赖 B1 裁定） | 阻塞中 |

**可以立刻继续的**：P1 只读档的两个 backend 实现。它不触及 owner 门控（B1 只影响写档）、不触及 Gateway 契约（只读命令本地放行）、不依赖引擎归属（B3 已被零依赖设计规避）。

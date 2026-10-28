# Android HostProfile Probe 设计

- **状态**：Draft —— P0 已按本设计落地（`crates/acowork-android/src/host/`），实现期发现 3 处契约缺口需回写本文，见下方「实现期修订」
- **日期**：2026-10-20（原标 `2026-05-15` 与所引 ADR-AND-001 同期，该日期不成立，理由见该 ADR 头部）
- **相关**：[ADR-AND-001](../../adr/zh/ADR-AND-001-android-host-profiles-and-execution-backend.md)
- **目的**：定义「启动时一次性能力探测」的探测项、数据契约、失败语义与消费方式，使工具列表与 shell 方言描述由**实测**生成，而非硬编码平台判断。

---

## 1. 为什么需要显式探测

Android 宿主的差异不是「桌面 vs 移动」这种二分，而是连续谱：

- 同一台设备可以是 user / userdebug / eng 版；
- Root 方案可以是 MagiskSU / KernelSU / SuperSU / 无；
- 命令集可以是 toybox / busybox / 二者皆有 / 二者皆无；
- SELinux 可以是 enforcing / permissive，且**root 仍受域策略约束**。

任何硬编码的 `if android then shell = false` 都会在这一连续谱上出错。上游 `docs/design/zh/12-tool-system.md` 已定义了「Runtime 启动 → 检测平台 → 构建可用工具列表 → 注入 System Prompt」的流程，本设计是它在 Android 分支上的具体化，**不新增机制，只补细节**。

---

## 2. 探测项

| # | 探测项 | 命令 | 解析要点 | 失败语义 |
|---|---|---|---|---|
| 1 | uid / gid | `id -u` | 0 = 特权进程 | 探测本身失败 → 退回 `apk-sandbox` |
| 2 | SELinux 模式 | `getenforce` | `Enforcing` / `Permissive` / 命令不存在 | 不存在 → `Selinux::Unknown`，写档能力一律不开放 |
| 3 | 当前安全域 | `cat /proc/self/attr/current` | 期望 `u:r:untrusted_app:s0` / `u:r:shell:s0` / `u:r:magisk:s0` | 读不到 → 视为受限域 |
| 4 | su 可用性 | `su -c 'id -u; cat /proc/self/attr/current'` | 记录 su 后的 uid **与域**（二者可能不同） | 超时 / 拒绝 → 不提供 `root-shell`；**弹窗被拒不可重试** |
| 5 | shell 方言 | `/system/bin/sh --version`、`command -v bash` | 区分 mksh / bash / busybox sh | 无可用 shell → 不注册 shell 工具 |
| 6 | 命令集 | `toybox` / `busybox` + `ls`（applet 列表） | 得到实际存在的 applet 集合 | 两者皆无 → 仅 shell 内建，工具描述需说明 |
| 7 | 可写挂载 | `mount` 解析 + `touch` 试探 | `/data` 可写；`/system`、`/` 是否可 remount | 不可写 → 不开放 `android:fs:system` |
| 8 | 构建类型 | `getprop ro.build.type` | `user` / `userdebug` / `eng` | — |
| 9 | 可调试性 | `getprop ro.debuggable`、`ro.secure`、`ro.adb.secure` | `ro.debuggable=1` 是调试档的强信号 | — |
| 10 | verity 状态 | `getprop ro.boot.veritymode`、`dm-verity` 设备节点 | `e`（enforcing）→ 写系统需 disable-verity + 重启 | 未知 → 保守按 enforcing |
| 11 | API / ABI | `getprop ro.build.version.sdk`、`ro.product.cpu.abi` | 决定二进制与 applet 行为差异 | — |
| 12 | 存储根 | `$PREFIX`、`/sdcard`、`/data/data/<pkg>` 可达性 | 得到 `fs_roots` 白名单 | — |

**探测预算**：全部探测串行执行应 < 2s；每项独立超时（建议 500ms），单项超时不阻塞整体，降级为 `Unknown`。

---

## 3. 数据契约

```rust
/// 探测结果：一次生成，会话期内只读。
pub struct HostProfile {
    pub name: HostProfileName,        // ApkSandbox | Termux | RootShell
    pub privilege: Privilege,         // AppUid | ShellUid | Root
    pub selinux: SelinuxState,        // Enforcing | Permissive | Unknown
    pub context: Option<String>,      // /proc/self/attr/current 原值
    pub shell: Option<ShellDialect>,  // Bash | MkSh | BusyBoxSh | None
    pub applets: AppletSet,           // 实际存在的命令名集合（toybox ∪ busybox ∪ 系统）
    pub fs_roots: Vec<FsRoot>,        // 可读写根，含 writable: bool
    pub caps: CapabilitySet,          // 见 §4，由以上事实推导
    pub device: DeviceFacts,          // build_type / debuggable / api / abi / verity
}
```

> ### 实现期修订（2026-10-28，评估 B8/B12）
>
> 落地 P0 时发现本节契约有两处不足，代码已按修订后实现，**本文待回写**：
>
> 1. **`shell` 单值字段无法表达 ADR §4.5 的双工具注册（B8）。** §4.5 要求注册 `bash` 与 `ash` 两个独立工具，而 `shell: Option<ShellDialect>` 只能存一个。已增加 `dialects: BTreeSet<ShellDialect>`，`shell` 保留为「主方言」（裸 `shell` 工具绑定的那一个）。
> 2. **`fs:system` 与 `selinux:permissive` 的推导规则漏了 shell 前置条件（B12）。** remount 意味着*执行* `mount`，`setenforce` 同理；无 shell 的宿主无论如何做不到——这正是 ADR §7.3 陈述为事实的那句话。缺这个前置条件会让 APK 档声明一个无法行使的能力，即上游 design 30 §11.1 警告的「能力谎报」（比「没有能力」更伤信任）。修订后：
>    ```
>    android:fs:system          ← shell != None 且 verity != Enforcing 且 /system 实测可 remount
>    android:selinux:permissive ← shell != None 且 privilege >= Root 且 selinux == Enforcing
>    ```

**推导规则（关键：capability 是探测事实的函数，不是配置项）**

```
android:shell:read      ← shell != None
android:shell:write     ← caps 含 read 且 privilege >= Root（或 su 探测成功）
android:fs:outside-app  ← fs_roots 存在 writable 且不属于自身包目录
android:fs:system       ← verity != Enforcing 且 /system 实测可 remount
android:selinux:permissive ← privilege >= Root 且 selinux == Enforcing
```

---

## 4. 核心原则：探测 ≠ 保证

SELinux 是**运行时按 (scontext, tcontext, tclass) 判定**的，静态探测无法预测具体拒绝。因此必须确立两条语义：

1. **探测结果只用于「是否注册工具 / 是否声明能力」，不作为执行放行的依据。** 真实权限以命令实际 exit code + stderr 为准。
2. **执行期拒绝必须回灌**：`avc: denied { read } for ... scontext=u:r:magisk:s0 tcontext=u:object_r:system_data_file:s0` 需被结构化抽取，转成给模型的下一步提示（缺哪个能力 / 需要 permissive / 路径不在 fs_roots），并**累计到会话级的 observed-denials 账本**，供同会话后续门控参考（同一 tcontext 二次拒绝即提示「不要重试」）。

> ### 实现期修订（2026-10-28，评估 B10 + 一处分类缺陷）
>
> 1. **observed-denials 不能存在 HostProfile 里（B10）。** 本节原文要求「累计到 HostProfile 的 observed-denials」，但 §3 声明 profile「一次生成，会话期内只读」——二者不能同时成立。已改为独立的会话级 `DenialLedger`。这同时让 ADR §7.1 的隐私红线成为**结构性保证**而非「记得过滤」：明细根本不在被上报的 profile 里。
> 2. **「路径不在 fs_roots」这条提示必须加守卫。** §2 item 12 只探 `$PREFIX` / `/sdcard` / 自身包目录，因此 `fs_roots` 记录的是**非特权**可达范围，**不是** root 可达范围的穷举（README 矩阵写的是「`/data` 大范围」）。对能提权的宿主说「路径不对、提权也没用」，会把模型从唯一可行的修复上引开——这是实现期由测试抓到的真实缺陷。修订后该分支以「宿主无法提权」为前置条件；能提权时一律先建议提权。

> 反模式警告：若把探测当作保证，会形成「探测显示可写 → 模型反复试探 → 每次都吃 denied → 上下文被垃圾填满」的静默降级循环。这是本设计要显式阻断的。

---

## 5. 消费方式

### 5.1 工具注册

- `shell` 类工具按 `ShellDialect` 注册为**独立工具**（沿用上游 Windows 上 bash / powershell 双注册的范式）：`bash`（Termux）、`ash`（`/system/bin/sh`）。描述由 `applets` 动态生成，例如「本机 `/system/bin/sh` 为 mksh，命令由 toybox 提供，`sed -i` 需空参数、`find -printf` 不可用」。
- 未进入 `caps` 的能力对应工具**不注册**，模型看不到即不会调用（与上游「LLM 只能看到当前平台可用的工具」一致）。

### 5.2 System Prompt 注入

注入一段简短宿主摘要（建议 ≤ 10 行），包含：profile 名、privilege、SELinux 模式与域、可用 shell 方言、fs_roots、已开放 capability、以及「写操作需审批 / 危险命令默认拒绝」的声明。

### 5.3 上报 Gateway

**已定案**（见 ADR §7.1）：只上报**能力摘要** —— `profile` 名、`caps` 集合、`shell dialect`、`privilege` 等级。
**不上报**设备序列号 / 型号、`fs_roots` 具体路径、SELinux context 原字符串、observed-denials 明细。

上报主体是 **Node Agent**（宿主能力是节点属性，与具体 Agent 无关），Gateway 侧仅用于展示与筛选，
**不作为放行判定的依据** —— 权限判定始终在设备本地完成，避免两处权威漂移。

---

## 6. 缓存与失效

- 探测在 Runtime 进程启动时执行一次，结果随进程生命周期存活。
- 触发重探的事件：su 授权状态变化（用户改了 Magisk 策略）、`setenforce` 执行后、remount 执行后、设备重启后进程重启。
- **不做定时轮询**：探测含子进程派生，在移动端有功耗成本；且上述事件都是我们自己发起的，可在发起点主动重探（事件驱动优于轮询）。

---

## 7. 测试策略

| 层级 | 方式 |
|---|---|
| 单元 | 用伪造的探测输出（含缺失命令、超时、畸形 `mount` 文本）断言 `caps` 推导；探测解析器必须对「命令不存在」健壮 |
| 契约 | 三档 profile 各产出一份 `HostProfile` 快照，作为回归基线（真机：user 版 + Termux；userdebug + Magisk root；APK 沙箱） |
| 集成 | 断言 root-shell 档下**无常驻 root 进程**（`ps -Z` 检查 Runtime 自身域仍为 `untrusted_app`） |
| 故障注入 | su 弹窗被拒、`getenforce` 不存在、toybox/busybox 双缺失、`/system` remount 失败 —— 均须降级而非 panic，且错误信息可执行 |

---

## 8. 未决问题 → 已裁定

原三条未决问题已在 [ADR-AND-001 §7.5](../../adr/zh/ADR-AND-001-android-host-profiles-and-execution-backend.md) 定案：

1. **applets 探测粒度**：`toybox` + `busybox --list` 一次性取全量，再对 ≤10 个高价值命令做 `command -v` 抽查。逐个探测需上百次子进程派生，在移动端功耗不可接受；只信 `--list` 则会漏掉系统原生 `/system/bin/*`。
2. **APK 档文件操作是否走 `ExecutionBackend`**：**不走**，继续用 `std::fs`。文件操作不需要 shell，为「四件套语义一致」而强行统一属于抽象先行。
3. **su 变体支持面**：首版只支持 **MagiskSU** 语法（`su -c`）。KernelSU 兼容该接口故顺带可用；SuperSU 明确不支持。


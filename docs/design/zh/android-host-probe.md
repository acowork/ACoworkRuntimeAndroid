# Android HostProfile Probe 设计

- **状态**：Draft —— P0 已按本设计落地并按 [ADR-AND-002](../../adr/zh/ADR-AND-002-platform-contract-layer.md) 拆成两层（规则在 `crates/acowork-platform-contract/`，本文描述的探测项与推导规则在 `crates/acowork-android/src/host/`）。实现期发现的 3 处契约缺口已回写本文（§3 B8/B12、§4 B10）
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
| 3 | 当前安全域 | `cat /proc/self/attr/current` | 期望 `u:r:untrusted_app:s0` / `u:r:shell:s0` / `u:r:magisk:s0`；**输出以 NUL 结尾而非换行**（真机实测 `u:r:shell:s0\0`），`trim()` 与 `is_ascii_whitespace` 都不删 NUL，须经 `facts::normalize_context` 截断 | 读不到 → 视为受限域 |
| 4 | su 可用性 | `su -c 'id -u; cat /proc/self/attr/current'` | 记录 su 后的 uid **与域**（二者可能不同） | 超时 / 拒绝 → 不提供 `root-shell`；**弹窗被拒不可重试** |
| 4a | su 位置 | `command -v su` | 与 5a 同形：exit 0 且 stdout 非空才算存在。**必须是探测而不是 `stat`**：`RootShellBackend` 没有绝对路径就无法构造（子进程环境被清空，裸名解析不出来），而固定路径清单会漏掉 `PATH` 上的安装位置；harness 跑在手机上而非手机里时，本地 `stat` 问的还是错的文件系统 | 找不到 → `paths.su = None`，root 档不可用；**不得回落成一个"常见路径"** |
| 5 | shell 方言 | ~~`/system/bin/sh --version`~~ → `sh -c 'echo $KSH_VERSION; echo $BASH_VERSION'`、`command -v bash` | 区分 mksh / bash / busybox sh。`--version` **在真机上直接报错**（`sh: --: unknown option`，BLA-AL00 实测），mksh 的版本只能从内建变量取；变量未设置时输出空串，故两问一起问 | 无可用 shell → 不注册 shell 工具 |
| 6 | 命令集 | `toybox`（裸）/ `busybox --list` + `ls`（applet 列表） | 得到实际存在的 applet 集合。**两种写法不是一回事**：BLA-AL00 实测裸 `toybox` 返回 194 个**applet 名**，`toybox --list` 返回同样 194 项但带安装路径（`bin/cat`、`usr/bin/acpi`）。解析器要的是名字，改成 `--list` 会把路径当成 applet 名收进集合；输出按终端宽度折行（真机 19 行），须按空白切分而非按行 | 两者皆无 → 仅 shell 内建，工具描述需说明。**6c 抽查已落地**（`ProbeCommand::SpotChecks`，一条 shell 问 11 个 `command -v`）：BLA-AL00 实测 11 项全在 `/system/bin`，其中 **9 项不在任何 `--list` 输出里**（`logcat` `dumpsys` `getprop` `am` `pm` `input` `screencap` `settings` `bugreportz` 是系统原生二进制，不是 toybox applet）——只信 `--list` 会把这 9 项判成不存在 |
| 7 | 可写挂载 | `mount` 解析 + `touch` 试探 | `/data` 可写；`/system`、`/` 是否可 remount | 不可写 → 不开放 `android:fs:system` |
| 8 | 构建类型 | `getprop ro.build.type` | `user` / `userdebug` / `eng` | — |
| 9 | 可调试性 | `getprop ro.debuggable`、`ro.secure`、`ro.adb.secure` | `ro.debuggable=1` 是调试档的强信号 | — |
| 10 | verity 状态 | `getprop ro.boot.veritymode`、`dm-verity` 设备节点 | `e`（enforcing）→ 写系统需 disable-verity + 重启 | 未知 → 保守按 enforcing |
| 11 | API / ABI | `getprop ro.build.version.sdk`、`ro.product.cpu.abi` | 决定二进制与 applet 行为差异 | — |
| 12 | 存储根 | `$PREFIX`、`/sdcard`、`/data/data/<pkg>` 可达性 | 得到 `fs_roots` 白名单 | — |
| 13 | 证据源可达性 | `for p in /data/anr /data/tombstones /data/system/dropbox`：`ls -d`（在不在）→ `ls`（能不能列）→ `wc -l`（几条）→ `head -n 1 <首个文件>`（能不能读） | ADR §4.6 item 6 承诺采集这些源，但每一条都是**权限问题而不是存在性问题**，所以四步分别跑、逐条报 exit，而不是问一次「有没有」。**三步以上要合并成一次 shell 调用**：三个路径各四步是 12 次往返，为的是取一个事实，在电池上不划算。**BLA-AL00 实测**（`user` 档 / uid 2000 / enforcing / 无 root）：`/data/anr exists=0 list=0 count=3 read=1` → **文件名拿得到、一个字节都读不到**（三个 trace 全是 `-rw------- system system`）；另两径 `exists=1` → 连 `stat` 都被拒 | 三档都不是「可用」。无 root 时 `readable()` 是空集。写 `available` 是谎报；写 `unavailable` 会丢掉唯一能拿到的东西（ANR 发生过这件事，比 trace 的字节更能改变下一步）。enforcing 域下「没有这个文件」与「不许你看到这个文件」从内部看是同一种观测，`Absent` 因此是一个取值而不是两个 |
| 13b | `dumpsys` 服务清单 | `dumpsys -l` | `dumpsys <service>` 不是一条命令，是**一个每设备列表上的分发器**：BLA-AL00 实测 246 个服务。§4.4 把 `dumpsys` 当一条只读命令是对的（存在性由 6c 证明），但「这个设备上有没有你要 dump 的那个服务」是逐项的事，静态探测答不了 | 无表头 / 零条目 → `None` 而不是 `Some(0)`：拒答与「本机一个服务都没有」是两回事，而后者在 Android 上不存在 |

**探测预算**：全部探测串行执行应 < 2s；每项独立超时（建议 500ms），单项超时不阻塞整体，降级为 `Unknown`。

**预算的实测状态**（2026-10-29，BLA-AL00 经 adb；耗时由探测循环逐次记进 `ProbeOutput::costs`，随 fixture 一起提交）：

| 量 | 实测 | §3 的约束 |
|---|---|---|
| 只读集展开 | 20 次串行调用（写试探 7b 不在只读集里） | — |
| 总计 | **1217ms** | < 2s ✅ |
| 最慢单项 | **268ms**（探测项 13 的证据面批处理） | 单项 500ms ✅ |
| 触达超时的项 | 0 | — |

`the_probe_budget_was_met_on_real_hardware` 现在同时钉住**总时长**与**单项**，此前它只钉单项。这不是补测试细节，是原来那条断言答不了这个问题：「没有一项超时」与「总共花了多久」是两个问题——二十条各花 49ms 的命令一次都不会触达 500ms 超时，加起来仍然是一秒。旧文档在这里写的「~2s / 16 条」是估的。

两点值得记住：

1. **批处理买到的就是预算本身。** 探测项 13 按逻辑步数是 3 个路径 × 4 步 = 12 次往返，合并成一次调用实测 268ms，占整条预算的 22%；13b 的 `dumpsys -l` 约 199ms。要是各步单独走 adb，光这两项就会把预算吃穿。
2. **预算不是免费的。** 新增一项探测就是新增一次电量与延迟开销。加之前要能回答「这一项会改掉哪一句谎」——13 / 13b 的答案是 §4.6 item 6 那句「这六个源都能采集」，那是可执行的错误。答不上来的项别加。

`total_duration_ms()` 的口径要说清楚：它只覆盖串行命令循环，不含循环前那一次 `$PREFIX` 读取，也不含 `fs_roots` 的写试探（后者是另一批 runner 调用）。所以「整个探测花了多久」比这个数更大，报出来的时候别把它当成前者。


---

## 3. 数据契约

```rust
/// 探测结果：一次生成，会话期内只读。
pub struct HostProfile {
    pub name: HostProfileName,            // ApkSandbox | Termux | RootShell
    pub privilege: Privilege,             // AppUid | ShellUid | Root
    pub selinux: SelinuxState,            // Enforcing | Permissive | Unknown
    pub context: Option<String>,          // /proc/self/attr/current 原值
    pub domain: SelinuxDomain,            // 由 context 解析出的域（UntrustedApp | Shell | Magisk | …）
    pub shell: Option<ShellDialect>,      // 主方言：裸 `shell` 工具绑定的那一个
    pub dialects: BTreeSet<ShellDialect>, // 全部可用方言，供 ADR §4.5 的双工具注册（B8）
    pub applets: AppletSet,               // 实际存在的命令名集合（toybox ∪ busybox ∪ 系统）
    pub fs_roots: Vec<FsRoot>,            // 可读写根，含 writable / own_package
    pub su: SuProbe,                      // su 探测结果，含 prompt_denied（§2 item 4：被拒不可重试）
    pub system_remountable: bool,         // /system 实测可否 remount
    pub caps: CapabilityTable,            // 见 §4，由以上事实推导（契约层类型，见下方 2026-10-29 修订）
    pub device: DeviceFacts,              // build_type / debuggable / api / abi / verity
}
```

> ### 实现期修订（2026-10-29，[ADR-AND-002](../../adr/zh/ADR-AND-002-platform-contract-layer.md)）
>
> `caps` 的类型从本地的 `CapabilitySet` 换成契约层的 `CapabilityTable`，`HostProfile` 改为实现契约的 `HostDescription` trait。原因是本文档描述的东西分属两层：
>
> | 属于 | 内容 |
> |---|---|
> | **契约层**（平台无关） | 「能力必须由证据支持才可声明」（R4）、「探测决定声明、不决定放行」（R2）、「探测有界、一次、由事件失效而非轮询」（`ProbeBudget`）、「摘要不含设备标识」（R13） |
> | **本文档 + Android 层** | 探测**哪 12 项**、每项用什么命令、输出怎么解析、五个 `android:*` ID 的四轴取值、以及下面那张推导规则表 |
>
> 判据是一句话：换一个平台，上面那行不用改，下面那行全部重写。§4 的两条原则因此不再是本文档的约定，而是契约层的 R2 与 R9/R4，由 `tests/rules_conformance.rs` 逐条验证。

> ### 实现期修订（2026-10-28，评估 B8/B12 —— **已于 2026-10-29 回写本文**）
>
> 落地 P0 时发现本节契约有两处不足：
>
> 1. **`shell` 单值字段无法表达 ADR §4.5 的双工具注册（B8）。** §4.5 要求注册 `bash` 与 `ash` 两个独立工具，而 `shell: Option<ShellDialect>` 只能存一个。已增加 `dialects: BTreeSet<ShellDialect>`，`shell` 保留为「主方言」（裸 `shell` 工具绑定的那一个）。
> 2. **`fs:system` 与 `selinux:permissive` 的推导规则漏了 shell 前置条件（B12）。** remount 意味着*执行* `mount`，`setenforce` 同理；无 shell 的宿主无论如何做不到——这正是 ADR §7.3 陈述为事实的那句话。缺这个前置条件会让 APK 档声明一个无法行使的能力，即上游 design 30 §11.1 警告的「能力谎报」（比「没有能力」更伤信任）。
>
> 两处均已写入上面的 struct 与下面的推导规则表。

**推导规则（关键：capability 是探测事实的函数，不是配置项 —— 契约层 R1）**

```
android:shell:read         ← shell != None
android:shell:write        ← caps 含 read 且 privilege >= Root（或 su 探测成功）
android:fs:outside-app     ← fs_roots 存在 writable 且 !own_package
android:fs:system          ← shell != None 且 verity != Enforcing 且 system_remountable
android:selinux:permissive ← shell != None 且 privilege >= Root 且 selinux == Enforcing
```

每条规则都**必须附带证据**才能进入 `CapabilityTable`：契约层 `audit_claims` 是唯一入口，它会拒绝三类声明——未注册的 ID、被拒绝的探测（含 su 弹窗被拒）、以及过期证据（R4）。因此「推导规则」不是一段可以自由改写的业务逻辑，而是一组必须可举证的断言。

---

## 4. 核心原则：探测 ≠ 保证

SELinux 是**运行时按 (scontext, tcontext, tclass) 判定**的，静态探测无法预测具体拒绝。因此必须确立两条语义：

1. **探测结果只用于「是否注册工具 / 是否声明能力」，不作为执行放行的依据。** 真实权限以命令实际 exit code + stderr 为准。
2. **执行期拒绝必须回灌**：`avc: denied { read } for ... scontext=u:r:magisk:s0 tcontext=u:object_r:system_data_file:s0` 需被结构化抽取，转成给模型的下一步提示（缺哪个能力 / 需要 permissive / 路径不在 fs_roots），并**累计到会话级的 observed-denials 账本**，供同会话后续门控参考（同一 tcontext 二次拒绝即提示「不要重试」）。

> **这两条已上升为契约层规则（2026-10-29）**：第 1 条是 **R2**（探测不是保证；它决定*声明*什么，逐次授权是闸门 `Gate::decide` 的决定，每次请求都跑，不是启动时跑一次）；第 2 条是 **R9**（诊断随错误传递且可操作）与 **R4**（拒绝不支持声明）。
> 上升的意义在于它们不再是「Android 的设计选择」：任何平台挂进集群都必须满足，且由 `tests/rules_conformance.rs` 的 `r2_*` / `r4_*` / `r9_*` 测试逐条验证。第二个端口不能把这两条当作可选优化。

> ### 实现期修订（2026-10-28，评估 B10 + 一处分类缺陷）
>
> 1. **observed-denials 不能存在 HostProfile 里（B10）。** 本节原文要求「累计到 HostProfile 的 observed-denials」，但 §3 声明 profile「一次生成，会话期内只读」——二者不能同时成立。已改为独立的会话级 `DenialLedger`。这同时让 ADR §7.1 的隐私红线成为**结构性保证**而非「记得过滤」：明细根本不在被上报的 profile 里。
> 2. **「路径不在 fs_roots」这条提示必须加守卫。** §2 item 12 只探 `$PREFIX` / `/sdcard` / 自身包目录，因此 `fs_roots` 记录的是**非特权**可达范围，**不是** root 可达范围的穷举（README 矩阵写的是「`/data` 大范围」）。对能提权的宿主说「路径不对、提权也没用」，会把模型从唯一可行的修复上引开——这是实现期由测试抓到的真实缺陷。修订后该分支以「宿主无法提权」为前置条件；能提权时一律先建议提权。

> 反模式警告：若把探测当作保证，会形成「探测显示可写 → 模型反复试探 → 每次都吃 denied → 上下文被垃圾填满」的静默降级循环。这是本设计要显式阻断的。

---

## 5. 消费方式

### 5.1 工具注册

- `shell` 类工具按 `ShellDialect` 注册为**独立工具**（沿用上游 Windows 上 bash / powershell 双注册的范式）：`bash`（`command -v bash` 解析到了才注册）、`ash`（有 shell 真正执行过就注册，绑定 `/system/bin/sh`）。**已实现**：[`host/tools.rs`](../../crates/acowork-android/src/host/tools.rs) 由 `HostProfile` 纯函数生成描述文本，内容是「方言是什么、§4.4 的哪些命令实测存在、哪些位置被 `touch` 证实可写、**证据源各能拿到什么**、跑在哪个 uid 与 SELinux 模式下」。
  证据那一行按 §4.6 item 6 的固定词表逐源点名并给出实测访问级（`/data/anr names only; /data/tombstones not reachable; …`），
  没探到的写 `not probed` 而不是从列表里消失——悄悄变短的清单会被读成「这台机器没有 dropbox」。
  BLA-AL00 上这一行的实际输出：`Evidence: /data/anr names only; /data/tombstones not reachable; /data/system/dropbox not reachable. \`dumpsys\` has 246 running services to dump from (each needs its own \`android:shell:read\` approval).`
  本文早期版本举的例子（「`sed -i` 需空参数、`find -printf` 不可用」）**没有进入实现**：那是 Android 传闻而非本机测量，错一次的代价是模型据此拒绝一条本来能跑的命令，或依赖一条本来不存在的限制。探测答不上来的，描述里就写「不知道」——例如 shell 跑成功了但方言没被认出（busybox ash 两个变量都不设），仍然注册 `ash`，只是写「探测未能识别方言」。
- 未进入 `caps` 的能力对应工具**不注册**，模型看不到即不会调用（与上游「LLM 只能看到当前平台可用的工具」一致）。

### 5.2 System Prompt 注入

注入一段简短宿主摘要（建议 ≤ 10 行），包含：profile 名、privilege、SELinux 模式与域、可用 shell 方言、fs_roots、已开放 capability、以及「写操作需审批 / 危险命令默认拒绝」的声明。

### 5.3 上报 Gateway

**已定案**（见 ADR §7.1）：只上报**能力摘要** —— `profile` 名、`caps` 集合、`shell dialect`、`privilege` 等级。
**不上报**设备序列号 / 型号、`fs_roots` 具体路径、SELinux context 原字符串、observed-denials 明细。

这条红线有**三个出口**，前两个是修出来的，第三个是量出来的。

**出口一 · 摘要**：`HostDescription` 只带 profile 名、caps、dialect、privilege。

**出口二 · 错误文案**：同样是设备本地拼好、原样过线的字符串，而且更容易写错——「把原因放进消息里」
看起来永远是对的。`BackendError::to_contract()` 曾把 `observed_context` 原串拼进 `BackendUnavailable`，
APK 档下即 `u:r:untrusted_app:s0:c166,c232`，而 MLS 分类是按安装分配的，那是设备指纹而不只是策略标签。
现在投影只输出 uid（2000 / 0 是平台常量）加域的**类别**（六值固定词表：shell / app-sandbox / su-magisk /
未识别 / 不可读 / 未观测），原串留在本地 `ExecRecord`、`Display` 与审计日志里。

**出口三 · 命令自己的输出**。这个出口此前是敞开的，而且敞在最宽的地方：`ExecRecord::to_contract()`
把 stdout / stderr 原样搬过线。avc 审计记录是内核写进 audit log 的，所以它到达本进程的方式不是「后端
出错」，而是**§4.6 item 6 让 agent 去跑的第一条取证命令的 stdout**——`logcat -d`。BLA-AL00 实测一次
`logcat -d -b events -t 400`：181 条审计记录（175 条 `avc: denied` + 6 条 `avc: granted`），含 181 处
`u:r:`、234 处 `u:object_r:`、23 处 `s0:c`，另有第三方应用私有目录的完整路径。这些全部原样进了 Gateway。

现在 `denial::redact_denials` 在投影处重写审计记录：保留权限集、对象类与目标的**类型**
（`system_prop`、`app_data_file`——平台 sepolicy 的词表，同版本每台设备都一样），丢掉 user / role /
MLS 区间与路径。非记录的行逐字节不动，包括 `ps -Z` 的输出：§7.1 禁的是拒绝明细，不是设备能打印的
每一个标签，而 agent 待在调试机上的一大目的就是看某个进程在哪个域里。三个细节：

1. `avc: granted` 参与脱敏但不进 `parse_denials`。同一对标签、同样的私有路径，只按「denied」匹配的红actor
   会自认为清干净了；而它也不是阻断，算进去会让端口去「修」一个策略允许了的访问。
2. dmesg 的双空格写法（`avc:  denied  {`）必须解析。只认单空格会把内核来源的拒绝读成「这里没有拒绝」，
   后果不是难看而是错报：`was_blocked_by_selinux()` 把被阻断的命令报成普通非零退出，模型于是无限重试。
3. 带 `scontext=` 却解析不出记录的行**整行扣下**。不能理解就放行，等于在这条规则唯一要保护的那个字段上
   fail-open。

**守门测试为什么差点没起作用**（值得单独记一笔）：`the_exec_error_path_never_leaks_device_detail_either`
当时断言的是 `!serde_json::to_string(&outcome).contains("u:r:")`，而 `ExecOutput.bytes` 是 `Vec<u8>`，
serde 序列化成数字数组——**任何内容都能通过这个断言**。它一路绿灯地放行了上面那 181 条记录。现在先解码
再断言（`fn streams`），并补了 `a_denial_that_arrived_on_stdout_is_redacted_there_too`、
`a_ps_dash_z_row_is_not_a_denial_and_keeps_its_labels`、
`a_logcat_dump_of_other_processes_denials_is_not_this_runs_block`。教训：对序列化后的字节串做「不含某子串」
的断言，默认它是无效测试，直到你看见它对错误的内容失败过一次。

`record.selinux_denials` 与脱敏是两个问题，不要合并：前者是「内核拒绝了**这条命令**什么」（读它自己的
stderr），后者是「过线的字节里不许有标签」。logcat 里别人家的历史拒绝会被脱敏，但不会把这次成功运行
标成被阻断，也就不会附送一句「需要提权」。

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
| 契约 | 四档 profile 各产出一份 `HostProfile` 快照，作为回归基线（`root-shell`：userdebug + Magisk root；`termux`：user 版 + Termux；`system-shell`：user 版 `adb shell`，uid 2000 / mksh / 无 su；`apk-sandbox`：APK 沙箱内无 shell） |
| 地面实况 | `tests/fixtures/devices/huawei-bla-al00-api29.json` 是**真机逐字回包**（含 `attr/current` 的 NUL），`tests/device_ground_truth.rs` 用它逐字段对账。伪造 fixture 只能证明解析器自洽，证明不了它对上了任何一台设备——本文件的 §5 三处修正全部来自这次对账 |
| 集成 | 断言 root-shell 档下**无常驻 root 进程**（`ps -Z` 检查 Runtime 自身域仍为 `untrusted_app`） |
| 故障注入 | su 弹窗被拒、`getenforce` 不存在、toybox/busybox 双缺失、`/system` remount 失败 —— 均须降级而非 panic，且错误信息可执行 |

---

## 8. 未决问题 → 已裁定

原三条未决问题已在 [ADR-AND-001 §7.5](../../adr/zh/ADR-AND-001-android-host-profiles-and-execution-backend.md) 定案：

1. **applets 探测粒度**：`toybox` + `busybox --list` 一次性取全量，再对 ≤12 个高价值命令做 `command -v` 抽查。逐个探测需上百次子进程派生，在移动端功耗不可接受；只信 `--list` 则会漏掉系统原生 `/system/bin/*`。
   **已实现并被真机证实**：抽查（探测项 6c）与批量列表合并进 `ShellPaths.applets`，一次往返 117ms。真机漏检率 9/11——`logcat` 等 9 个命令确实不在任何 `--list` 里。名单的选法因此有两条：先要 §4.4 能力词汇表或 §4.6 item 6 的证据源真的用到它，再看**别的探测项是否已经证明过它**。`mount` 因此让出了位置——探测项 7 本身就执行 `mount` 并解析挂载表，它的存在早被"跑成功"这件事回答了，抽查只是再问一遍；而 `settings` 是 §4.4 写档点名的命令、任何列表都看不见；`bugreportz` 是 §4.6 item 6 点名的证据源、同样任何列表都看不见，它加入时把上限从 10 抬到 12（抬上限要付出一句理由，这条规则也写在 `probe.rs` 的名单测试里，不然它会只在文档里活着）。`ps` 与 `setprop` 虽然出现在 `--list` 里，仍然保留：列表是 dispatcher 自述的表，`command -v` 问的是 shell 实际要解析的文件系统，两者是否一致是设备相关的偶然。
2. **APK 档文件操作是否走 `ExecutionBackend`**：**不走**，继续用 `std::fs`。文件操作不需要 shell，为「四件套语义一致」而强行统一属于抽象先行。
3. **su 变体支持面**：首版只支持 **MagiskSU** 语法（`su -c`）。KernelSU 兼容该接口故顺带可用；SuperSU 明确不支持。


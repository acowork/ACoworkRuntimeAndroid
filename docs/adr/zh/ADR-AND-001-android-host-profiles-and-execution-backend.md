# ADR-AND-001: Android Host Profiles 与 ExecutionBackend（含高权限调试档）

- **状态**：**部分 Accepted** —— §1–§6（宿主档位、一个引擎、工具级提权、`ExecutionBackend` 契约）有效并已落地 P0；档位由三档扩到四档，见 §4.3；⚠️ **§7.1 与 §7.4 待与上游对齐**，二者被晚于本 ADR 的上游文档推翻，详见下方「上游冲突」与 [开发就绪度评估](../../review/zh/2026-10-28-readiness-assessment.md) B1/B2。
- **日期**：2026-10-20（原标 `2026-05-15` 有误：正文引用了 2026-09-13 才创建的 ADR-075、2026-10-05 的 ADR-087、2026-10-09 的 ADR-090，该日期不可能成立）
- **相关**：[README.md](../../../README.md)、上游 `docs/design/zh/12-tool-system.md`（平台支持矩阵与运行时平台检测）、上游 `core/acowork-runtime/src/tools/builtin/shell.rs`（多 shell 注册范式）、上游 ADR-087（node/agent 归属与门控）、上游 `docs/design/zh/30-runtime-protocol-and-pluggable-engine.md`（能力注册表与可插拔引擎，**v0.2 直接点名本 ADR**）、session 参数 `shellApprovalThreshold` / `approvalTimeoutSecs`
- **实现**：P0 已交付，并按 [ADR-AND-002](ADR-AND-002-platform-contract-layer.md) 拆成两层 —— 规则在 `crates/acowork-platform-contract/`（平台中立，只依赖 serde，可在裸机 target 编译），Android 的事实与机制在 `crates/acowork-android/src/host/`（探测解析器、capability 取值、`su -c` 包装、`avc` 回灌）。468 测试通过，clippy `-D warnings` 零告警，并在华为 BLA-AL00 上端到端验证。本 ADR §7.1/§7.4 的门控落点已从 `backend.rs` 迁至契约层 `gate.rs`，§4.4 的权限描述已细化为四轴 `CapabilitySpec`——**决策内容不变**，详见 ADR-AND-002 §4
- **EN mirror**：待补 `docs/adr/en/`（上游 `AGENTS.md:142` 要求中英 ADR 同一 commit 更新；本仓库尚未采用该约定，见评估 B7）

> ### ⚠️ 上游冲突（2026-10-28 核对）
>
> 本 ADR 提交于 2026-10-20。此后上游有两份文档修订，均与本 ADR 冲突：
>
> | 上游 | 日期 | 冲突点 |
> |---|---|---|
> | design 30 v0.2 §6.2 / §9 | 2026-10-24 | 「新增能力的唯一路径是注册表 PR」「能力是布尔开关，不带参数」；并明确要求本 ADR §7.1 的能力上报「**应改为**同一份能力注册表的一个来源」 |
> | ADR-087 v3 D1/D5 | 2026-10-28 | 「执行点 = Gateway 反代入口，Runtime 不引入 owner 概念」「owner 不进 MQTT proto，Node 不感知用户」——与本 ADR §7.4「设备本地判定请求者是 node owner」及 §7.1「Gateway 不做门控判定」不能同时成立 |
>
> **已采用的解法**（见评估 B1/B2）：把 §7.4 的合取项拆成两个权威——Gateway 判*归属*（下发不透明布尔裁决，设备看不到 owner 身份，满足 ADR-087 D1/D5），设备判*本地就绪*（`dangerous-mode` ∧ 写锁 ∧ 探测事实），最终合取在设备侧完成（原 `authorize`，现为契约层 `Gate::decide`，见 [ADR-AND-002](ADR-AND-002-platform-contract-layer.md) §4）。capability 则保留为本仓库自己的领域类型，不绑定上游 `Permission` 封闭 enum；到最终注册表的映射层待 B2 裁定后再建，因此裁定倒向任一边都只需改一个文件。
>
> 影响面：**仅 P3 写档**。P0/P1/P2 只读档不触及 owner 门控，不受阻塞。

---

## 1. 背景与问题

本仓库当前设计以 **Termux** 作为 CLI 版本的 shell 宿主：安全性与兼容性好，但权限低，Agent 只能操作
应用自身目录（`$PREFIX` / app 私有目录）。

存在第二类场景：**调试用的 Android 设备**（eng / userdebug 版本，已 Root，带 busybox 或 toybox）。
这类场景需要读取全量 logcat、dumpsys、跨应用数据目录、setprop、am/pm/input/screencap，甚至修改系统分区。

要回答的问题：

> 能否用「真实 Android 命令行环境 + busybox」做一个高权限的 Android Runtime，用于 Android 系统开发调试？

### 1.1 必须先纠正的三个技术前提

| 常见假设 | 实际情况 | 对设计的影响 |
|---|---|---|
| Root = 全能 | Android 上真正的门槛是 **SELinux 域**，不是 uid。`adb shell` 位于 `shell` 域；`su` 后进入 Magisk 注入的 `u:r:magisk:s0` / `u:r:su:s0` 域；**root 进程仍受策略约束**，`avc: denied` 照旧出现 | 提权能力必须**探测**（`getenforce`、`/proc/self/attr/current`），不能假设「有 su 就全通」；`setenforce 0` 需作为独立高危能力单独审批 |
| `/system` 可写 | user 版只读 + dm-verity / AVB；`mount -o remount,rw /system` 需先 `disable-verity` 并重启；A/B 与动态分区使「改系统」退化为刷 image 级操作 | 「写系统分区」必须是显式能力 + 显式前置检查 + 显式回滚路径，不能由模型自由试探 |
| busybox ≈ 标准 Linux | `/system/bin/sh` 是 **mksh**（POSIX 子集，与 bash 语法存在差异）；Android 6+ 自带 **toybox**，与 busybox applet 参数不兼容（`sed -i`、`find -printf`、`stat -c` 等语义不同） | 不能伪装「一个 shell 通吃」。需注册为**两个独立工具**，各自带方言说明，交由模型选择 |

---

## 2. 约束与目标

**功能目标**

- F1：在 Root 设备上，Agent 可执行真实 Android 命令行（mksh + toybox/busybox）与系统级调试命令。
- F2：在普通设备上，行为与现有 Termux 方案完全一致，零回归。
- F3：同一份引擎代码同时支撑两种宿主，不产生第二套 Runtime 语义。

**非功能目标**

- N1（安全）：提权范围可声明、可审批、可审计；默认最小权限。
- N2（可回滚）：任何设备级变更都有明确恢复路径；不可逆操作默认拒绝。
- N3（可运维）：诊断信息（uid / SELinux 域 / verity 状态 / 拒绝原因）随错误一并返回。
- N4（契约稳定）：与 Gateway 的协议契约不变，Gateway 不感知宿主档位。

**显式非目标**

- 不做「把整个 Runtime 跑在 root 下」的形态（理由见 §4.1）。
- 不在本阶段引入 Magisk 模块打包管线。
- 不引入通用「插件式 shell 框架」——只解决三个已知宿主档。

---

## 3. 备选方案

### 方案 A：Termux 宿主 + `su -c` 提权 helper（**推荐**）

Runtime 仍以非特权身份跑在 Termux 内；仅 `shell` / 文件写入工具通过 `su -c` 无状态提权执行。

- ✅ 改动最小：只新增一个 `ExecutionBackend` 实现。
- ✅ 复用 Termux 现成的网络 / DNS / 包管理 / wake-lock 栈。
- ✅ 攻击面收敛：常驻网络进程不持有 root；root 只存在于单条命令的生命周期内。
- ✅ 文件属主不被污染（只有子命令是 root，Runtime 自身写出的文件仍是 app uid）。
- ⚠️ Magisk 授权弹窗可能反复出现（需会话级授权 + 常驻 daemon 兜底，见 §7）。
- ⚠️ 依赖设备上已装 Termux。

### 方案 B：独立静态二进制，`adb shell su -c` 拉起整个 Runtime

- ✅ 不依赖 Termux；权限最完整（进程级 magisk 域）。
- ❌ adb 会话断开即进程退出，保活需自行解决（`nohup` / init service），与 Android 生命周期无集成。
- ❌ 常驻进程持有 root + Gateway 凭证 + LLM key + loopback HTTP 服务：一次 prompt injection = 整机沦陷。
- ❌ root 写出的 config / log / workspace 属主为 uid 0，下次非特权启动读不到、删不掉。
- ❌ 需自建交叉编译与 `.so` 分发管线。

### 方案 C：Magisk 模块（init service + magisk 域常驻）

- ✅ 保活最强，适合长期挂机的设备农场。
- ❌ 新增模块打包 / 签名 / OTA 兼容 / 多 Magisk 变体（MagiskSU、KernelSU、SuperSU）适配成本。
- ❌ 与方案 B 同样的进程级 root 攻击面问题。

### 方案 D：不做高权限档，调试场景交给 adb + 人工

- ✅ 零成本。
- ❌ 放弃本场景的全部价值：无法闭环「复现 + 证据采集 + 关联分析」，Agent 在调试场景退化为聊天工具。

### 对比

| 维度 | A | B | C | D |
|---|---|---|---|---|
| 改动量 | 小 | 中 | 大 | 无 |
| 保活 | 复用 Termux | 差 | 强 | — |
| 攻击面 | 命令级 | 进程级 | 进程级 | 无 |
| 属主污染风险 | 低 | 高 | 高 | — |
| 调试场景价值 | 高 | 高 | 高 | 低 |

---

## 4. 决策

### 4.1 核心决策：三种 Host Profile，一个引擎，工具级提权

**Termux / APK 沙箱 / Root-Shell 是同一 Runtime 的三种宿主能力档（Host Profile），差别只在执行后端与权限边界，不在引擎语义。** 不新增第三个二进制，不新增第三个 crate，README 的「两个交付物」结构保持不变——Root 档是 CLI 版本的**一种运行模式**。

同时确立一条不可妥协的安全原则：**Runtime 主体保持非特权，只有工具执行下沉到提权 helper。**

理由：

1. Runtime 持有 Gateway enrollment 凭证与 LLM API key，在 loopback 上开 HTTP 服务，并直接执行来自远端的指令。整体 root 化后，提示注入的爆炸半径从「Agent 工作区」扩大到「整机 + 系统分区」。
2. 权限范围越大，越难界定「本次会话到底改了什么」。提权只发生在工具调用瞬间，审计边界才清晰。
3. 上游契约要求「Gateway 不感知对端是手机」，变的应当只是 capability 集合。

### 4.2 架构

```mermaid
graph TD
    subgraph Core["acowork-android 共享引擎（非特权）"]
        Loop["LLM 主循环 / 记忆 / Intent / MQTT"]
        Probe["HostProfile Probe 启动时能力探测"]
        Iface["trait ExecutionBackend"]
        Gate["Capability Gate + 审批 + 审计"]
    end
    Loop --> Gate --> Iface
    Probe -.->|"注入可用工具列表与 shell 方言"| Loop
    Iface --> P1["ShellBackend: app uid; bash+PREFIX (termux) or mksh (system-shell)"]
    Iface --> P2["AppSandboxBackend: scoped storage, 无 shell"]
    Iface --> P3["RootShellBackend: su -c mksh + toybox/busybox"]
    P3 --> Broker["提权 helper：su -c（无状态）"]
    P3 --> Tools["Android 调试工具集 logcat / dumpsys / prop / screencap"]
```

依赖方向：backend 实现依赖 `ExecutionBackend` 契约；引擎不依赖任何具体 backend。
这与上游「接口优先的依赖方向」以及 README 中「平台相关代码收敛在 trait 之后，保留干净的上游回流路径」一致。

### 4.3 能力矩阵

| 能力 | apk-sandbox | system-shell（新增） | termux | root-shell（新增） |
|---|:---:|:---:|:---:|:---:|
| shell 执行 | ❌ | ✅ mksh（`/system/bin/sh`） | ✅ bash | ✅ mksh + toybox/busybox |
| 文件范围 | app 私有目录 | 探测证实可写的根（真机：`/data/local/tmp`、`/sdcard`、`/storage/self/primary`） | `$PREFIX` + 用户授权 SAF | `/data` 全域；`/system` 需 remount |
| 跨 app 数据（`/data/data/*`） | ❌ | ❌（uid 2000，Enforcing） | ❌ | ✅（SELinux 允许时） |
| logcat 全量 | ❌ | ✅（实测：shell uid 在 user 版上读到的是全量缓冲区，含其他进程的日志行） | 仅本 app | ✅ |
| setprop / am / pm / input / screencap | ❌ | ❌（无 su） | ❌ | ✅ |
| 绕过 Doze | ❌（FGS 受限） | 未验证 | 依赖 Termux wake-lock | ✅（需显式策略与审批） |
| 风险等级 | 低 | 中 | 中 | **高（可 brick）** |

> `system-shell` 这一档是接了真机之后加上的：一台 user 版、无 Termux、无 root、但 `adb shell`
> 可用的设备（uid 2000 / mksh / Enforcing）。在此之前它被归进 `termux`，于是
> `HostSummary.profile` 对上游声称了一个装了 Termux 的环境——而探测项 5a（`command -v bash`）
> 与 13（`$PREFIX`）都没有观察到它。**档位名不是装饰**，它进每一条 exec 记录；声称一台设备
> "不是"什么，和编造一个不存在的路径是同一类错误。
>
> 标"未验证"的那一行是诚实的空位：Doze 行为在这台机器上没有实测过。`logcat` 一行原本是同样的
> 空位，后来在设备上量过了——结论比预想的宽（shell uid 读到的是全量缓冲区），所以这一格现在是
> 实测值而不是推断。列在此处的意义不在于填满，而在于说明**哪些格是量出来的、哪些还是推的**。

### 4.4 权限模型：把 root 拆成可审批的 capability

禁止 `root: true` 这类布尔量。沿用上游 `filesystem:read:<path>` 的粒度风格，新增：

| Capability | 覆盖范围 | 默认 |
|---|---|---|
| `android:shell:read` | getprop / dumpsys / logcat / ps / df / mount / getenforce | 白名单自动放行 |
| `android:shell:write` | setprop / am start / pm install / settings put / input | **需审批** |
| `android:fs:outside-app` | 写 `/data` 下非自身路径 | 需审批 + 自动备份 |
| `android:fs:system` | remount、写系统分区 | 需 dangerous-mode 会话开关 + 逐条审批 |
| `android:selinux:permissive` | `setenforce 0` | 逐条审批，会话结束自动恢复 |

审批机制**复用** session 已有的 `shellApprovalThreshold` / `approvalTimeoutSecs`，不新造一套审批子系统。

**「白名单自动放行」按脚本内容判定，不按标签判定**（`crates/acowork-android/src/host/commands.rs`）。`ExecRequest::read()` 只是调用方的自我声明；若只读标签就能拿到执行权，把 `setprop` 标成 read 即绕过全部审批，白名单形同虚设。后端在派生进程前解析脚本本身：逐段（`;` `|` `&&` `||` 换行）取命令词，绝对路径取基名，`toybox`/`busybox` 多路复用器解包成真正的子命令，再按命令 + 标志位 + 子命令定效果（`logcat -c` 清缓冲、`mount -o remount` 重挂、`pm install`、`settings put`、任何重定向到文件）。自称 read 而内容含写 → 拒绝并指名缺哪一档能力；含**无法解析**的结构（命令替换、反引号、嵌套 shell、`if`/`for`）判为 `Opaque`，**任何档位都不放行**——解析不了就无法证明它只做读，这是 fail-closed 而非保守。写标签下 §4.6.3 的硬禁列表同样直接拒绝，且不附「可升级到 X 档」的提示。效果之间按 §4.4 的档位排序比较（`shell:write` 覆盖它自带的读），过度声明（写标签跑纯读脚本）不拒：多花一次审批，不伤害任何人。

### 4.5 工具注册：复用上游双 shell 范式

上游 `shell.rs` 在 Windows 上已把 Git Bash 与 PowerShell 注册为**两个独立工具、各自带描述**，让模型有依据地选择并 fallback。Android 直接沿用：

- `bash`：Termux 环境，POSIX + bash 扩展。
- `ash`：`/system/bin/sh`（mksh），显式声明「无 bash 数组、`[[` 语义差异、命令由 toybox/busybox 提供」。

工具描述由 HostProfile Probe 的探测结果动态生成（哪些 applet 真实存在），而非硬编码。 **已实现**（`crates/acowork-android/src/host/tools.rs`）：描述是 `HostProfile` 的纯函数，只写测到的事实——解释器路径与方言、§4.4 读写词汇表里哪些命令实测存在、哪些根目录被 `touch` 证实可写、§4.6 item 6 的每个证据源实测能拿到什么（`names only` / `not reachable` / `readable` / `empty` / `not probed`，逐源点名，没探的也占一位——悄悄变短的清单会被读成「这台机器没有 dropbox」）、运行的 uid 与 SELinux 模式。两条注册规则：解析不出路径就不注册（后端清空子进程环境，裸名无法解析）；探测没有答案就写「不知道」，不写 Android 传闻。BLA-AL00 实测生成的 `ash` 描述见 `cargo run --example device_probe` 第 5 节。

### 4.6 调试场景护栏（rollback-first）

1. **审计日志**：每条提权命令记录 `capability / 实际 uid / SELinux 域 / 命令 / exit code / 耗时 / avc 拒绝`。 **已实现**（`crates/acowork-android/src/host/audit.rs`）：字段此前就齐备，缺的是出口，现在出口是一条策略而不只是文件。`AuditedBackend` 装饰器包住任何 `ExecutionBackend`（写进装饰器而非各后端内部，因为三个后端各自记得记账不叫控制；且最值得记的那批拒绝来自共享的内容检查，按后端记会整个漏掉无 shell 的 `AppSandboxBackend`）。每次尝试落**两条**记录：进入后端**之前**写 `attempted`，出结果后写 `completed` / `refused` / `privilege_not_granted` / …。开口记录写不下去时命令**不执行**——那是唯一还来得及拒绝的时刻，可跳过的审计是日志不是护栏；而收尾记录写不下去**不**改写成失败：命令已经跑了，把记账失败说成命令失败会诱导调用方重试一次已经发生的改动，只累计 `failures()`。存储是限长的 JSONL（默认 1 MiB，超限丢最旧的行，在半容量处轮转以免逐行重写）——手机的 /data 不是日志桶。拒绝的分类也补上了：`BackendError::Refused` 原先只带 `to_string()` 的结果，把「有人试图 §4.6.3 硬禁的分区破坏命令」「模型贴错档位」「分类器看不懂脚本」三件性质完全不同的事压成一句话，现在额外携带 `RefusalKind`。真机（BLA-AL00）第 6 节实测：读命令 `attempted`+`completed`（uid 2000 / `u:r:shell:s0`）、误标写 `refused(mismatch)`、硬禁 `refused(banned)`，第四条对着一个拒绝写入的 sink 确实没有到达设备。
2. **拒绝归类**：从 stderr 抽取 `avc: denied`，转成可执行的下一步提示（「需要 su 域」/「需要显式 permissive 审批」），避免模型盲目重试。 **部分实现**：抽取已落地并接进 `ExecRecord::selinux_denials`（`backends::to_record`，一处解析、所有后端共享；现在也认 dmesg 的双空格写法，只认单空格会把内核来源的拒绝读成「没有拒绝」，于是被阻断的命令被报成普通非零退出、模型无限重试）；`classify` + `DenialLedger`（同一目标重复命中的检测）已实现并由 `tests/rules_conformance.rs` 的 R9 逐条验证，但**生产调用点还没接上**——端口桥（把 `ExecRecord` 变成契约调用的一方）尚未建立，所以归类目前只在测试里跑。过线文案里现在有的是 `SelinuxDenial::summary` 的脱敏形式（权限集 / 对象类 / 目标类型），它带得动「下一步」但不含「提权」建议：建议提权需要知道这台机器能不能提权，那是 `classify(denial, profile)` 的输入，而投影处没有 profile。
3. **硬禁列表**：`dd of=/dev/block/*`、`rm -rf /data`、`wipe data`、`fastboot`、分区 `flash` —— 默认拒绝，即使 dangerous-mode 也需人工确认 + 设备指纹匹配。 **已实现**（`commands::Effect::Banned`）：`fastboot` / `flash` / `mkfs` / `format` 与任何含 `wipe-data` 的参数命中即拒；`dd` 看 `of=` 指向、`rm` 看删除目标是否为设备根或分区根、重定向落进分区路径同样判禁——删应用自身目录这类正常写不受影响。拒绝措辞不给出任何可达路径。
4. **写操作可撤销**：改 prop 前记录旧值，会话结束自动回滚（`persist.*` 需显式声明才保留）；改文件先备份到 Agent 工作区，提供 `restore`。
   **已实现**（`crates/acowork-android/src/host/rollback.rs`）：三步，顺序本身就是内容——**先捕获**（写之前是最后一个还能知道旧值的时刻）、**按结果记录**（失败的写没改任何东西，给它准备 undo 会在收尾时多出一笔真实的写）、**后恢复**（LIFO：同一 prop 被改两次，中间那个状态是真实存在过的，按记录顺序恢复会把它留在中间态）。`ReversibleBackend` 是装饰器而不是三个后端各写一遍，理由与审计日志同一条：三处各自记得捕获就是三次忘记的机会，而忘掉的那一处会把设备留在改过的状态。几个决定值得记下来：逆操作**复用原审批令牌**——让人重新批准他批准过的事情的反面不是安全，是训练他闭眼点确认，而他睡着时设备就停在改过的状态；**读不到前态就不建 undo**，恢复到一个没人观察过的值是第二次未经批准的改动，不叫回滚；`setprop k ''` 只是近似（Android 没有 unset，`getprop` 看不出区别而 `/prop` 能），所以标 `faithful: false` 而不是假装等价；`settings get` 的 `null` 表示行不存在，所以精确逆操作是 `delete` 而不是写入四个字符；SELinux 处于 disabled 时 `setenforce` 没有逆操作，此时诚实的答案是 `CannotUndo` 而不是跑一条内核忽略的命令再报成功；**拆不开的脚本是「没看见」而不是「干净」**，`Unundoable` 按会话留着并在收尾点名，因为一个空账本和一次什么都没改的会话长得一模一样。
   **与闸门的关系**：R8 只对标了 `Irreversible` 的能力强制 `rollback_plan`，Android 上只有 `android:fs:system` 是这一档——那里的诚实计划是「刷回官方 image」，要模型把这句话打出来正是为了说明没有代码能替它撤销。`setprop` / `settings put` 标的是 `Reversible`，闸门读作「不要求」，所以此前能力表里的「可逆」是对一个尚未存在的模块的断言，而不是对设备的事实；现在它有了所指。`denial.rs` 给模型的 `setenforce 0` 提示里那句「is restored automatically at session end」此前同样是空头承诺——拒绝文案里的承诺是最不该出现未实现功能的地方，因为模型会把它当成世界的属性来定价。
   **仍未实现的两半**：文件写（§4.6.4 的「备份到 Agent 工作区 + `restore`」）没有逆操作模型，`am` / `pm` / `input` 一类也不存在「把广播放回去」的脚本，它们都进 `Unundoable`；`ReversibleBackend` 目前只被单测和真机 harness 第 9 节驱动，node 入口还没组装 `Rollback(Audit(Shell))` 这条链，所以写档在生产里仍未开放。真机（BLA-AL00，第 9 节只跑捕获、不跑任何写）：`setprop debug.stagefright.ccodec 1` 前态空串 → 近似逆操作；`settings put system font_scale 1.6` 前态 `1.0` → `settings put 'system' 'font_scale' '1.0'`；`setenforce 0` 前态 `Enforcing` → `setenforce 1`。
5. **DeviceWriteLock**：root 操作作用于**整机全局状态**，多个 Agent 并发调试会互相踩踏。Node Agent 侧新增 per-device 写锁，串行化 mutating 命令（read 类不锁）。锁由 **session 持有**、TTL 10 分钟、拿不到锁立即失败不排队 —— 语义详见 §7.2。这是本决策引入的**新架构件**。
6. **证据采集**：`logcat -d`（带 buffer / filter）、`screencap`、`dumpsys <service>`、`/data/anr`、`/data/tombstones`、`bugreportz`。这是 root 档的真正价值——把「复现 → 证据 → 关联分析」闭环。
   **实测校正（探测项 13 / 13b，2026-10-29）**：这一行把六个源写成了并列的「可采集」，实际是六个权限问题，而且答案各不相同。BLA-AL00（`user` 档 / uid 2000 / enforcing / 无 root）：`/data/anr` 能列出 3 个文件名、**一个字节都读不到**（每个 trace 都是 `-rw------- system system`）；`/data/tombstones` 与 `/data/system/dropbox` 连 `stat` 都被拒。所以「这是 root 档的真正价值」这句是对的，但它的反面也要写下来：**无 root 时这六个源里没有一个能取到内容**，能取到的只有「某时刻发生过 ANR」这种索引级事实。`dumpsys <service>` 另有一层：它不是一条命令而是一个每设备列表上的分发器（实测 246 个服务），存在性由 6c 证明，具体某个服务在不在只能问这台机器。工具描述按实测访问级逐源点名（`names only` / `not reachable` / `readable` / `empty` / `not probed`），既不写「available」也不写「unavailable」——前者是谎报，后者会丢掉唯一拿得到的东西。六个源里 `bugreportz` 是唯一一个「列表看不见」的：它是独立的 `/system/bin` 二进制，不在 BLA-AL00 那 194 个 toybox applet 名里，所以它现在进了 6c 抽查名单（此前只有抽查能回答它，而当时没人问）。它也不是只读源——分类器把它判在写档（生成一份报告不是读取某份报告），需要 `android:shell:write` 与审批；工具描述里这一句是从分类器读回来的，不是另写一遍文案，因为描述与闸门两个所有者一旦各说各话，模型就会照描述去要一个闸门根本不会批准的审批。

### 4.7 提权 helper 契约（窄接口）

```text
exec {
  script,             // 经 stdin 传入，禁止放入 argv（ps 可见，会泄露敏感参数）
  cwd, env, timeout,
  capability,         // 声明所需能力，用于门控与审计
  approval_token,
} -> {
  stdout, stderr, exit_code,
  selinux_denials[],  // 从 stderr 结构化抽取
  uid, context,       // 实际执行上下文，用于自证
  duration_ms,
}
```

起步为**无状态 `su -c`**（每次约 50–100ms 开销）。仅当实测证明开销或弹窗骚扰成为问题时，再引入常驻 daemon（loopback unix socket + token），遵循 rule-of-three。

---

## 5. 后果

**正面**

- 高权限调试场景成立，且 Termux 方案零回归。
- 引擎仍是一份，上游回流路径清晰：新增的是 trait 实现与 capability 声明，不是新分支逻辑。
- 权限从「布尔 root」变成可审计的 capability 集合，安全性优于「整体 root 化」的直觉方案。

**负面 / 需承担**

- 引入 HostProfile Probe 这一新组件，必须保证探测结果与实际执行一致（探测通过但执行被 SELinux 拒绝是常态，需明确降级语义）。
- DeviceWriteLock 是跨 Agent 的全局资源，其归属门控与上游 ADR-087 的叠加方式已在 §7.4 定案（双条件与、默认拒绝），实现时不可各自解释。
- Magisk 授权 UX 无法由我们控制（弹窗、会话时长由 Magisk 决定），需在文档中明确告知用户。
- 支持面扩大：toybox / busybox / 各 Root 方案的行为差异会持续产生兼容性 bug。

---

## 6. 验证与交付顺序

**先只读、后可写**——只读档已能覆盖 logcat / dumpsys / 属性查看等绝大多数系统调试诉求，且几乎无 brick 风险。

| 阶段 | 范围 | 验证方式 |
|---|---|---|
| P0 | `ExecutionBackend` trait + HostProfile Probe | 单元测试用伪造 probe 输出；真机四档（user 版 adb shell / user 版 + Termux / userdebug+root / APK 沙箱）快照对比；已实测的是第一档，见 `tests/fixtures/devices/` |
| P1 | `RootShellBackend` 只读档（`android:shell:read`） | 真机跑通 getprop / dumpsys / logcat；断言无 root 进程常驻 |
| P2 | Android 调试工具集 + 审计日志 | 结构化日志可复现每条命令的 capability 与上下文 |
| P3 | 写档 + 审批 + DeviceWriteLock + 自动回滚 | 故障注入：会话中断后 prop 回滚生效；并发双 Agent 争锁不互相污染 |
| P4 | Magisk 模块形态（**仅当**设备农场需求成立） | 暂缓，YAGNI |

**回滚路径**：`RootShellBackend` 是独立可选实现，未启用时引擎行为与现状完全一致；出问题可通过配置直接退回 Termux 档，无需回退代码。

---

## 7. 遗留问题裁定

以下四条在评审前是开放问题，现全部定案（含被否掉的选项与理由）。

### 7.1 HostProfile 是否上报 Gateway → **上报能力摘要，不上报设备细节**

> ⚠️ **本节两处裁定已被上游推翻，待对齐**（评估 B1/B2）：
> ①「Gateway 不做门控判定」与上游 ADR-087 D5「执行点 = Gateway 反代入口」冲突；
> ②「上报能力摘要」的词汇表所有权已归上游 design 30 §6.2 的能力注册表，该文档 §9 明确要求本节「**应改为**同一份能力注册表的一个来源」。
> 「上报什么 / 不上报什么」的隐私红线仍然有效并已落成测试（`gateway_summary_never_leaks_device_detail_on_any_tier`）。
>
> ⚠️ **红线有三个出口，前两个是修出来的，第三个是量出来的**（2026-10-29 复核）。摘要之外，错误文案同样是设备拼好、原样过线的字符串，而它更容易写错——「把原因放进消息里」看起来总是对的。`BackendError::to_contract()` 曾把 `observed_context` 原样插进 `BackendUnavailable` 文案，APK 档下即 `u:r:untrusted_app:s0:c166,c232`（MLS 分类是按安装分配的，那是设备指纹而不只是策略标签）；更糟的是当时有一条单测**断言了这个泄漏**，等于把错误行为钉成了基线。现在投影只输出 uid（2000/0 是平台常量，不是设备细节）加域的**类别**（六个固定取值，不含原串）；原串留在本地 `ExecRecord` 与 `Display`（N3 要真诊断，§7.1 只管离开设备的那一份）。补齐的守门：`the_exec_error_path_never_leaks_device_detail_either` 遍历所有 `BackendError` 变体与 `ExecRecord::to_contract()`，`an_mls_category_never_survives_the_contract_projection` 专门盯 APK 档形状。
>
> **出口三是命令自己的 stdout / stderr**，而它敞在最宽的地方：`to_contract()` 原样搬运两条流。avc 审计记录是内核写进 audit log 的，所以它到达本进程的方式不是「后端出错」，而是**本节 item 6 让 agent 去跑的第一条取证命令的输出**——`logcat -d`。BLA-AL00 实测一次 `logcat -d -b events -t 400`：181 条审计记录（175 `avc: denied` + 6 `avc: granted`），181 处 `u:r:`、234 处 `u:object_r:`、23 处 `s0:c`，外加第三方应用私有目录的完整路径，全部原样过线。守门测试当时**结构上不可能发现这件事**：它断言 `!serde_json::to_string(&outcome).contains("u:r:")`，而 `ExecOutput.bytes` 是 `Vec<u8>`，serde 写成数字数组——任何内容都能通过这个断言。现在先解码再断言，并由 `denial::redact_denials` 在投影处把审计记录重写成「权限集 + 对象类 + 目标类型」（`system_prop` 这类平台 sepolicy 词表，同版本每台设备相同），丢掉 user / role / MLS 区间与路径；非记录行逐字节不动（`ps -Z` 的输出保留：§7.1 禁的是拒绝明细，不是设备能打印的每个标签，agent 来这台机器部分就是为了看进程在哪个域里）。`avc: granted` 参与脱敏但不计入 `parse_denials`——同一对标签，且它不是阻断。细节与三条子决策见 [探测文档 §5.3](../../design/zh/android-host-probe.md)。

- **上报**：`profile` 名 + `caps` 集合 + `shell dialect` + `privilege` 等级。
- **不上报**：设备序列号 / 型号、`fs_roots` 具体路径、SELinux context 原字符串、`observed-denials` 明细。
- **上报主体是 Node Agent，不是 Runtime**：宿主能力是**节点属性**，与具体 Agent 无关。放在 Node 侧上报，避免每个 Runtime 各自重复声明同一事实造成不一致（也与上游 ADR-075 node identity、ADR-090 安装归属「能力归 Node」的方向一致）。
- **Gateway 只用它做展示与筛选，不做门控判定**：真正的放行决策始终发生在设备本地。若 Gateway 也维护一份权限判断，就会出现两处权威、必然漂移。

> 否掉的选项：完全不上报。理由是 Gateway 无法区分「能调试的节点」与「普通手机节点」，调度与 UI 只能盲选，Agent 被派到不具备能力的节点上后才在运行期失败——错误暴露得越晚，排查成本越高。

### 7.2 DeviceWriteLock 持有者语义 → **由 session 持有，TTL 10 分钟，不排队不抢占**

| 决策点 | 裁定 |
|---|---|
| 持有者 | **session**，不是 agent |
| TTL | 10 分钟；每条 mutating 命令执行时自动续期 |
| 拿不到锁 | **立即返回明确错误**（含持有者标识），不阻塞、不排队 |
| 超时后 | 只释放，**不自动抢占** |
| 实现落点 | Node Agent 进程内单点串行，**不引入分布式锁** |

理由：

- **session 而非 agent**：调试是有始有终的会话活动，而 agent 是常驻实体。若由 agent 持有，一个崩溃或忘记释放的 agent 会让整机写能力永久不可用，且无法解释「为什么这个 agent 占着设备」。
- **不排队**：排队会制造一条隐蔽的串行队列，命令在队列里等待时模型看不到失败原因，只会重复提交（典型的静默降级反模式）。快速失败 + 明确持有者信息，才能让模型或人去做「换设备 / 联系持有者」的正确决策。
- **不抢占**：抢占会打断他人的写序列（prop 改了一半、文件备份了但没写完），产生比死锁更难恢复的中间状态。宁可拒绝服务，不可破坏一致性。
- **进程内单点**：一台设备一个 Node Agent，串行点天然存在，引入分布式锁是纯粹的过度设计。

> **实现落点补注（2026-10-29，见 [ADR-AND-002](ADR-AND-002-platform-contract-layer.md)）**：本节语义已拆成两层。TTL、不排队、不抢占、过期回收是**平台无关规则**（R11），落在契约层 `exec::ResourceLock`；「持有者是 session」和「错误里含持有者标识」是**端口概念**——契约层的锁没有身份，因为 session 在别的平台上未必存在。Android 侧 `SessionWriteLock` 包一层契约锁，只加 session 身份。
> 这个拆分正是本节「拿不到锁要含持有者标识」这条要求逼出来的：契约锁若自带身份，就等于把 Android 的 session 模型强加给 ESP32。

### 7.3 dangerous-mode 是否需要 APK UI 开关 → **不做，首版仅 CLI flag**

- 形态：`--dangerous-mode` CLI flag + 环境变量兜底（供 CI 使用），**每次会话显式开启**，不做持久化配置。
- 理由：**APK 档根本没有 shell，也没有 su**，`android:fs:system` 在 APK 上不可达。给它做 UI 开关是为一条不存在的路径加配置项（YAGNI），还会误导用户以为勾上就能改系统。等 APK 侧真的出现提权路径时再议。

### 7.4 `android:fs:system` 与 ADR-087 owner 门控如何叠加 → **双条件与，默认拒绝**

> ⚠️ **本节按字面不可实现，已改为两权威分解**（评估 B1）：ADR-087 D1/D5 规定 owner 真相只存 Gateway、不进 MQTT proto、「Runtime 不引入 owner 概念」，因此设备本地无法评估「请求者是 node owner」这一合取项。
> **保留的**：双条件与、默认拒绝、无主设备一律不开放、fail-closed。
> **修订的**：归属条件由 Gateway 判定并下发**不透明布尔裁决**（`AttributionVerdict`，不含 user id / owner 名 / 角色），设备侧只判本地就绪并完成合取。布尔裁决不是用户身份，故 ADR-087「Node 不感知用户」依然成立；最终放行仍在设备，故本节立场也成立。
> 落点：契约层 [gate.rs](../../../crates/acowork-platform-contract/src/gate.rs) 的 `Gate::decide`（原 `backend.rs` 的 `authorize` 已按 [ADR-AND-002](ADR-AND-002-platform-contract-layer.md) §4 上移，这是 R7 的执行点）。
> 测试：`r7_the_conjunction_happens_on_the_device_and_neither_authority_suffices`（双条件与 + fail-closed，含「问不到控制面不等于同意」）、`r7_the_attribution_verdict_carries_no_identity`（ADR-087 D1/D5：裁决不含身份）、`r7_a_verdict_cannot_be_replayed_against_a_higher_tier`（裁决按档定域，`use` 档不能用于 `manage` 档）、`system_tier_is_refused_on_the_termux_baseline_because_the_fact_is_missing`。均在 [rules_conformance.rs](../../../crates/acowork-android/tests/rules_conformance.rs) 与 [host_profile_contract.rs](../../../crates/acowork-android/tests/host_profile_contract.rs)。
> 原引的 `system_tier_needs_both_dangerous_mode_and_attribution` / `unowned_node_never_opens_the_system_tier_even_when_rooted_and_flagged` 两个测试名已在重排中被上述测试取代。

```
放行 = 设备本地开关（dangerous-mode 已开） ∧ 归属门控（请求者是 node owner）
```

- **无主设备（unowned node）一律不开放** `android:fs:system` 与 `android:selinux:permissive`，即使设备已 root、即使本地开了 dangerous-mode。
- **owner 身份不自动获得写系统能力**：owner 还必须在设备上显式启用 dangerous-mode。
- 任一侧缺失即拒绝（fail-closed），与 ADR-087「默认拒绝、未登记路由 fail-closed」的立场一致。
- 两侧分工：**归属门控管「谁能碰这台机器」，本地开关管「这台机器是否允许被改系统」**。前者在 Gateway，后者在设备，互不越位。

### 7.5 附带裁定（原属 [HostProbe 设计](../../design/zh/android-host-probe.md) §8）

1. **applets 探测**：`toybox` + `busybox --list` 一次性取全量，再对 ≤10 个高价值命令做 `command -v` 抽查。不做逐个探测（上百次子进程派生，移动端功耗不可接受）。
2. **APK 档的文件操作**：继续走 `std::fs`，**不**强行统一到 `ExecutionBackend`。文件操作不需要 shell，为「四件套语义一致」而统一是抽象先行于需求。
3. **su 变体支持面**：首版只支持 **MagiskSU** 语法（`su -c`）。KernelSU 因兼容 MagiskSU 接口顺带可用；**SuperSU 明确不支持**（已停止维护，不值得为其保留兼容分支）。

---

## 8. 剩余风险（不设决策，仅跟踪）

- Magisk 授权弹窗的 UX 与时长策略由 Magisk 决定，我们无法控制，只能在文档中告知用户并建议设置会话级授权。
- toybox / busybox / 各 ROM 的行为差异会持续产生兼容性 bug；缓解手段是探测 + 拒绝归类，而非穷举适配。
- `setenforce 0` 一旦获批，其影响范围是整机而非本进程，且可能被其他进程长期依赖——故其审批粒度定为**逐条 + 会话结束自动恢复**。


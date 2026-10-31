# Android Runtime 设置面盘点（APK 形态）

> 状态：设计已定，落地点已实现（[`host/config.rs`](../../crates/acowork-android/src/host/config.rs)）。
> 关联：[ADR-AND-001](../adr/zh/ADR-AND-001-android-host-profiles-and-execution-backend.md) §4.4 / §4.6 / §7.3 / §7.4、
> [android-host-probe.md](android-host-probe.md)、
> [readiness 评估](../review/zh/2026-10-28-readiness-assessment.md) B4。
> 日期：2026-11-02

## 0. 为什么要先盘点，再画界面

这是一个 runtime，不是一个 app。用户不会在手机上操作它，操作它的是 Gateway 那一头的 Agent。
所以 APK 上的界面**不是产品界面，是运维面板**：它的唯一职责是让持有这台设备的人知道
"这个节点现在被允许做什么、做到什么程度、东西存在哪儿"，并且能改其中真正属于他决定的那部分。

盘点先于画界面，是因为**"能改"这个能力本身有安全代价**。一个设置项如果能把设备事实写成
`rooted: true`，那它就不是设置项，是提权路径。所以本文件的主活是划界，不是罗列。

## 1. 两类值：设备答的 vs 人答的

| | 谁能回答 | 落在哪个类型 | 可否出现在设置界面 |
|---|---|---|---|
| 这台设备**是什么**：uid、SELinux 域、verity、applet 集、可写根、`su` 是否给了 root | 设备，被探测 | `HostProfile` | ❌ 只读展示可以，输入框不行 |
| 这个 runtime **被允许**怎样：占用多少空间、等多久、留哪些证据、开放哪几档能力 | 人，在界面上 | `HostConfig` | ✅ |

这条界是全部设计的前提。`derive_claims()` 只读左列；如果左列可写，设置界面就成了伪造能力声明的
入口——正是 readiness 评估 B12 反复强调的"能力谎报比没有能力更伤信任"。

## 2. 现状盘点

"性质"一列区分**测量值**（数字来自某台真机的某个观察）与**口味值**（没人测量过它）。
测量值可以被调小（用户有权少留），但把它调大往往意味着"这台设备给不了"，所以要有上界。

### 2.1 容量与预算（当前硬编码）

| 参数 | 现在在哪 | 默认 | 性质 | 开放？ | 理由 |
|---|---|---|---|---|---|
| 快照存储总预算 | `rollback.rs:88` `SNAPSHOT_STORE_BUDGET_BYTES` | 8 MiB | 口味 | ✅ | 手机剩余空间差异极大，8 MiB 不是普适承诺 |
| 单文件快照预算 | `rollback.rs:77` `SNAPSHOT_BUDGET_BYTES` | 64 KiB | 测量 | ❌ | 超过它就不快照，是**分类器精度**问题不是容量问题；开放会让人误调成"备份更大文件" |
| 快照分片大小 | `rollback.rs:98` `SNAPSHOT_CHUNK_BYTES` | 48 KiB | 测量（100 KiB 可达 / 128 KiB `Argument list too long`） | ❌ | 设备 argv 上限，与用户意愿无关 |
| 审计文件上限 | `audit.rs:89` `DEFAULT_MAX_FILE_BYTES` | 1 MiB | 口味 | ✅ | 留多久是运维决定；太小会丢可重建性 |
| 单条命令文本截断 | `audit.rs:83` `MAX_COMMAND_BYTES` | 4 KiB | 口味 | ❌ | 影响的是证据完整性口径，改它等于改"审计记什么"，属于策略不属于配置 |
| 证据采集预算 | `evidence.rs:63` `DEFAULT_EVIDENCE_BUDGET` | 4 MiB（实测 bugreport zip 4 093 129 B） | 测量+口味 | ✅ | 是否愿意让一次采集占 4 MB 是人的决定 |
| 证据分片 | `evidence.rs:69` `EVIDENCE_CHUNK_BYTES` | 256 KiB | 测量 | ❌ | 传输通道上限 |
| 单命令输出上限 | `backend.rs:95` `DEFAULT_OUTPUT_CAP` | 1 MiB | 口味 | ✅ | 直接决定 `dumpsys` 大输出留不留得下 |

### 2.2 时间（当前硬编码）

| 参数 | 现在在哪 | 默认 | 性质 | 开放？ | 理由 |
|---|---|---|---|---|---|
| 命令超时 | `backend.rs:88` `DEFAULT_READ_TIMEOUT` | 30 s | 口味 | ✅ | 慢设备 / 大分区上 30 s 会误杀 |
| 写锁 TTL | `backend.rs:85` `WRITE_LOCK_TTL` | 600 s | 口味 | ✅ | TTL 是死人开关：太短会抢占活跃会话，太长会让崩溃设备被锁住一小时 |
| bugreport 超时 | `evidence.rs:77` `BUGREPORT_TIMEOUT` | 300 s（实测 1 m 44 s） | 测量 | ✅ | 有下界（30 s）与上界（900 s）；开 bugreport 的人应该能等 |
| 快速证据超时 | `evidence.rs:79` `QUICK_TIMEOUT` | 30 s | 测量 | ❌ | 与命令超时同义，两个入口只会造成不一致 |
| 探测单项/总预算 | `probe.rs` `PROBE_ITEM_TIMEOUT` / `PROBE_TOTAL_BUDGET` | — | 测量 | ❌ | 探测是启动动作，不是运维参数；开放后"探测超时"会变成用户制造的假阴性 |

### 2.3 路径与位置

| 参数 | 现在在哪 | 默认 | 开放？ | 理由 |
|---|---|---|---|---|
| 快照目录 | **未定义**（`chain::wrap` 收 `snapshot_dir` 参数，无人传） | — | ✅ **子目录名** | 见 §4 规则 2：绝对路径由宿主给，界面只给名字 |
| 审计文件 | **未定义** | — | ✅ 子目录名 | 同上 |
| 证据落盘目录 | **未定义** | — | ✅ 子目录名 | 同上 |
| 设备侧暂存目录 | `evidence.rs:72` `EVIDENCE_STAGING_DIR`、`rollback.rs:104` `SNAPSHOT_STAGING_DIR` = `/data/local/tmp` | — | ❌ | 唯一实测 shell 可写且跨档位可用的位置；换掉就破坏快照链路 |
| `su` 候选路径 | `profile.rs:139` `SU_CANDIDATES` | 5 条 | ❌ | 探测候选集，属于左列（设备事实） |
| 可写根候选 | `adb.rs:77` `CANDIDATE_ROOTS` | — | ❌ | 同上 |

### 2.4 传输与目标设备（仅 adb 形态）

| 参数 | 现在在哪 | 默认 | 开放？ | 理由 |
|---|---|---|---|---|
| `adb` 二进制路径 | `adb.rs:187` `ACOWORK_ADB` | `adb`（PATH） | ✅ | 实测就不在 PATH 上（`/private/tmp/platform-tools/adb`），必须能指 |
| 设备序列号 | `adb.rs:187` `ACOWORK_ADB_SERIAL` | 无（单设备） | ✅ | 多设备并存时是唯一寻址手段 |
| Termux `$PREFIX` | `adb.rs` `read_termux_prefix()` 探测 | — | ❌ | 设备事实 |

> 注意：APK 形态在设备上直接执行，**没有 adb 这一层**。这两项属于"从桌面驱动手机"的开发/运维形态，
> 界面上应放在"远程驱动"分组，默认折叠。

### 2.5 能力与档位

| 参数 | 现在在哪 | 默认 | 开放？ | 理由 |
|---|---|---|---|---|
| 能力上限（ceiling） | `capability.rs` `derive_claims()` 纯事实推导，**无人可设** | 全部按事实 | ✅ **只允许收紧** | 见 §4 规则 1 |
| `dangerous-mode` | 契约层 `LocalReadiness.dangerous_session`，注释写明 "Never persisted" | 关 | ❌ **禁止持久化** | ADR-AND-001 §7.3 已裁定"不做 APK UI 开关"；本文用类型结构把它钉住（§5） |
| 归属裁决 | Gateway 下发 `AttributionVerdict` | 无主=拒 | ❌ | 设备端不可见，也不该可见（ADR-087 D1/D5） |
| 审批模式 | 契约层 `ApprovalRequirement`，每条能力已定 | 逐条 | ❌ | 写进设置就等于给用户一个"跳过审批"复选框 |
| 硬禁列表 | `commands.rs` `Effect::Banned` | 恒拒 | ❌ | `fastboot` / `mkfs` / `dd of=/dev/block` 等，§4.6.3 要求"即使 dangerous-mode 也要人工确认" |
| 只读白名单 / 分类器表 | `commands.rs` | — | ❌ | 这是安全边界本体，不是配置 |

### 2.6 证据来源（隐私面）

这一组是**唯一默认值全部取"窄"的分组**，因为它决定"这台手机主动往外送什么"。

| 来源 | 命令 | 现在 | 默认开放？ | 理由 |
|---|---|---|---|---|
| 截屏 | `screencap -p` | 可用 | ✅ | 排障刚需，且是当场可见的内容 |
| 日志 | `logcat -d` | 可用 | ✅（默认尾 200 行） | 整 buffer 实测 878 KiB，含其他应用输出 |
| `dumpsys <service>` | 单服务 | 可用 | ✅ | 需要指定服务，不是全量 |
| 设备文件 | `/data/anr/*`、`/data/local/tmp/*` | 可用 | ❌ | 本轮实测：`/data/anr` 里 root 属 0666 的 trace 能直接读出**别的进程的栈** |
| bugreport | `bugreportz` | 可用 | ❌ | 4 MB、1 m 44 s、整机个人信息；必须是显式选择 |

`logcat_tail_lines` 的语义是**默认值而非上限**：调用方明确写了 `-t N` 就按它，`0` 表示"我要全部"。
把它做成上限会让排障场景没法用，做成默认值才符合"界面替不会填的人填一个安全的数"。

## 3. 设置界面草图

四组，一共 13 行可编辑 + 一段只读的设备事实。没有"高级设置"折叠层——上面盘点的
不可开放项，界面上根本不出现，而不是灰掉（灰掉会引发"怎么开"的追问，而答案是不该开）。

```
设备（只读）           Android 10 / API 29 / user / uid 2000 / mksh / SELinux enforcing
                       能力：shell:read ✅  shell:write ❌  fs:outside-app ✅  fs:system ❌
                       （fs:system：设备本身不具备 —— 非用户可改）

能力上限               [x] 只读系统检查        android:shell:read
                       [x] 变更类 shell       android:shell:write
                       [x] 应用目录外写入      android:fs:outside-app
                       [ ] 系统分区写入        android:fs:system        （仍需会话级 dangerous-mode + 归属裁决）
                       [ ] SELinux permissive android:selinux:permissive（同上）

存储                   快照目录名     snapshots     预算 8 MiB      [64 KiB – 1 GiB]
                       审计目录名     audit        上限 1 MiB      [32 KiB – 256 MiB]
                       证据目录名     evidence     预算 4 MiB      [256 KiB – 512 MiB]
                       单命令输出     1 MiB                        [4 KiB – 64 MiB]

时间                   命令超时       30 s          [1 – 600]
                       写锁 TTL       600 s         [30 – 3600]
                       bugreport 等待 300 s         [30 – 900]

证据                   [x] 截屏  [x] logcat 尾 200 行  [x] dumpsys
                       [ ] 设备文件（/data/anr 等）   [ ] bugreport

远程驱动（默认折叠）    adb 路径  ______            设备序列号  ______
```

**"设备（只读）"那一段是界面最重要的部分**：它把"设备不具备"和"你关掉了"分开说。
`HostConfig::blocked_by_settings()` 就是为这一行存在的——它列出设备已挣到但被上限关掉的能力，
其余缺席项由 `explain_absence()` 给出设备侧理由。

## 4. 三条规则（已实现，非愿望）

### 规则 1：设置只能收紧，永远不能放宽

`HostConfig::claims(profile)` = `derive_claims(profile) ∩ ceiling`。
交集的两个操作数里，profile 不可编辑，所以把 `fs:system` 勾上而设备没有 root，**产出是空**。
这不是校验规则，是数据结构决定的性质；`a_ceiling_cannot_claim_what_the_device_never_earned`
用一台无 shell 的设备 + 全开上限钉住它。

反过来（顺序写错、或改成并集）设置界面就变成提权路径，所以这个测试是本文件里最不能删的一个。

### 规则 2：路径是"宿主根目录 + 子目录名"，界面不接收绝对路径

设置文档里只有 `"snapshots"` 这样的名字。根目录由宿主提供：
设备上是 app 私有数据目录，桌面驱动时是 Agent workspace。
`check_subdir()` 拒绝绝对路径、`/`、`\`、`.`、`..` 和非 `[A-Za-z0-9._-]`。

理由不是洁癖：一个能输入 `/data/system/x.conf` 的设置项，就是产品里权限最高组件内嵌的一个
任意文件写原语。`an_absolute_directory_name_is_refused` / `a_traversing_directory_name_is_refused`
钉这条。

### 规则 3：`dangerous-mode` 不在配置里

契约层 `LocalReadiness` 的字段注释写着 "Never persisted"，ADR-AND-001 §7.3 裁定 APK 不做这个开关。
本端口用**类型没有这个字段**来落实，并加一个会失败的测试：`{"dangerous_mode": true}` 必须解析失败
（`deny_unknown_fields`），默认文档序列化后不得出现 `dangerous` / `owner` / `root` / `bypass` 字样。
这样将来谁想加这个字段，会先撞上一个写明理由的测试，而不是顺手加进 struct。

## 5. 落地状态

| 项 | 状态 |
|---|---|
| `HostConfig` / `StorageConfig` / `BudgetConfig` / `TimingConfig` / `EvidenceConfig` 类型 | ✅ `host/config.rs` |
| JSON 读写 + `deny_unknown_fields` + 全字段边界校验（错误带点号路径） | ✅ `from_json` / `to_json` / `validate` |
| 能力上限与推导的交集 | ✅ `claims()` / `blocked_by_settings()` |
| 证据策略对来源的过滤与收窄 | ✅ `EvidenceConfig::apply()` |
| **快照存哪儿**（P3 未决项之一） | ✅ `prepare(root)` 建目录 + `SnapshotStore::with_budget` |
| **审计 sink 落盘策略**（P3 未决项之一） | ✅ `FileAuditSink::with_max_bytes`，目录随 `prepare` 创建 |
| **`ReversibleBackend` 组装点**（P3 未决项之一） | ✅ `chain::wrap_with_store` + `PreparedHost::chain`；`assemble()` 给 shell 档 |
| 档位不由配置决定 | ✅ `assemble()` 只建 shell backend；root 档需调用方显式经 `PreparedHost::chain` |
| 设置文档不含 dangerous-mode 的结构性保证 | ✅ `the_document_has_no_way_to_persist_dangerous_mode` |
| **超时与输出上限真正落到执行点** | ✅ `run_script` 的 `effective_budget()`：请求仍带端口默认值时替换为操作者的值，调用方明确写过的不动 |
| 设置文档的读写闭环 | ✅ `HostConfig::load(root)` / `save(root)`，固定文件名 `settings.json`；`load` 返回 `LoadSource`（文件 or 默认），界面必须显示是哪一种 |

**`load` 的不对称是有意设计的**：文件不存在 → 默认值；文件存在但读不动 → **报错，绝不回落到默认值**。
前者是首次开机，没人做过任何决定，默认值就是诚实答案。后者是操作者已经把快照预算调到 512 MiB，
而文件被手工改坏 / 被崩溃截断 / 由更新版本的界面写下——这时若静默回到 8 MiB，
设备就在"报告正在使用你的配置"的同时悄悄换了策略。**在一个人正信任的设备上静默改策略，
是配置加载器唯一不能做的事**。同理 `save` 先 `validate()` 再落盘：保存按钮是最可能输入非法值的地方，
写下去就等于制造一个"本次运行没问题、下次重启后加载失败退回默认值"的设备。
`a_broken_document_is_an_error_rather_than_a_quiet_return_to_defaults`、
`a_path_that_is_not_a_readable_file_is_not_treated_as_first_boot`、
`save_refuses_an_impossible_document_before_it_reaches_the_disk` 分别钉住这三条。

**最后一行是本轮踩到的坑，值得单独记。** `HostConfig` 刚写完时，`command_timeout_secs` 与
`output_cap_bytes` 有默认值、有边界、有测试——但没有任何地方读它们：`ExecRequest::new` 在
`backend.rs:164` 自己塞了 `DEFAULT_READ_TIMEOUT`/`DEFAULT_OUTPUT_CAP`，而**端口自己生成的请求**
（快照捕获、会话结束的 restore，见 `rollback.rs:1825`/`:1886`）全都走这条默认路径。
也就是说界面上那两行是死控件，而且是最坏的一种死法：看起来生效、测试全绿、真机上 30 秒就把
restore 杀了。

修法不是"让调用方记得传"。调用方包括端口自己，而端口内部的请求不可能每一处都改成读配置——
那正是"策略没人咨询就是撒谎的设置项"的成因。落点选在 `run_script`（每个 shell backend 唯一的
必经路径），判据是"请求带的还是不是端口默认预算"：

- 是 → 用操作者的值。覆盖端口内部所有请求，包括捕获与恢复。
- 不是 → 保留调用方的值。`evidence::capture` 明确要 300 s（实测 bugreport 1 m 44 s），
  把它压回界面里的 30 s 等于让一个设置静默拒绝它本来被打开来允许的事。

两个方向各有一个测试钉住：`the_command_timeout_in_the_settings_is_the_one_that_kills_the_child`
（断言的是 `SpawnInvocation.timeout`——真到孩子身上的那个数）与
`a_caller_that_named_a_budget_is_not_overruled_by_the_screen`。
已知可接受的碰撞：调用方显式选了恰好等于端口默认的值、而操作者改过它时，操作者的值生效。
| CLI flag 接线（`--host-config <file>`） | ⬜ 属上游 node crate，与 `NodeConfig` 一并做 |
| APK 设置界面本体 | ⬜ 需 B4 产品对齐（与 `apps/acowork-mobile` 的形态关系） |

## 6. 与上游 `NodeConfig` 的边界

上游 `core/acowork-node/src/config.rs` 已有 `NodeConfig`（`--home` / `ACOWORK_NODE_HOME`、
gateway host/port、token、name、proxy/LSP 端口、日志轮转）。**本端口不重复这些**：

| 参数 | 归属 |
|---|---|
| Gateway 地址 / 端口 / 配对 token / 节点名 / `--home` | 上游 `NodeConfig`，设置界面直接渲染它 |
| 能力上限 / 快照与审计与证据的目录名与预算 / 超时 / 证据策略 | 本端口 `HostConfig` |
| 根目录（`HostConfig` 里所有名字的父目录） | 上游 `NodeConfig.home` 决定，宿主传入 |

也就是说 APK 设置界面 = `NodeConfig`（连接与身份）+ `HostConfig`（这台设备上的行为），
两个文档、一个界面。这条边界必须写死，否则会出现"两处都能设 home"的经典分裂。

## 7. 未决

1. **B4 形态归属**：APK 是 `apps/acowork-mobile` 长出 host mode，还是独立包。本文件只定义
   **配置面**，不预设答案——`HostConfig` 是纯 Rust 类型，两种形态都能消费（JNI 侧一次
   `to_json`/`from_json` 即可）。
2. **界面语言与文案**：`ConfigError.reason` 现在是英文（与端口其余诊断文本一致）。设置界面若做
   中文，需要一份 reason → 文案的映射表，而不是把中文塞进库。
3. **预算的"当前用量"读数**：✅ 已有——`SnapshotStore::used_bytes()` 与
   `FileAuditSink::used_bytes()` 都是从文件系统读，不是内存计数；轮换丢行时二者才会不一致。
   界面可直接显示"快照已用 3.2 MiB / 8 MiB"。
4. **能力上限与 dangerous-mode 的界面耦合**：勾上 `fs:system` 但没开会话开关，界面应显示
   "已允许，但本会话未启用"。`explain_absence()` 目前只覆盖设备侧理由，配置侧的组合提示需要一条
   新文案路径。

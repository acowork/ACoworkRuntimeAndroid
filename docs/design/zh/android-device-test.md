# 真机测试手册（ACoworkRuntimeAndroid）

这份文档回答一个问题：**手边有一台手机时，怎么确认这个移植是真的而不是测试里的**。

先区分两件被混称为"真机测试"的事，它们的成本和结论完全不同：

| # | 名称 | 需要设备吗 | 证明什么 |
|---|---|---|---|
| A | 地面实况回放（`tests/device_ground_truth.rs`，15 个测试） | 不需要 | 解析器对得上**曾经真实测量过**的输出排版（`su` 缺失、applet 列表、props、SELinux 字段） |
| B | 活设备验证（`acowork-host` 二进制） | 需要 | 这台手机现在真的能被这条链路安全地驱动，并且写完能恢复 |

A 是回归防线，跑在 CI 里；B 是每次换设备、换 Android 版本、改分类器之后要手工做的事。下面按顺序做，每一步都给出**通过判据**——达不到判据就是发现问题，不是"测试没跑成"。

---

## 0. 准备（一次性）

```sh
cd /Users/nicholas/projects/ACoworkRuntimeAndroid
cargo build -q --bin acowork-host
export ACOWORK_ADB=adb                      # 或你的 platform-tools 绝对路径
export ACOWORK_ADB_SERIAL=<序列号>           # `adb devices` 的第一列；多机时必填
adb devices                                  # 状态必须是 device，不是 unauthorized
```

确认设备身份，后面所有判据都以此为前提：

```sh
adb -s "$ACOWORK_ADB_SERIAL" shell id
adb -s "$ACOWORK_ADB_SERIAL" shell getenforce
adb -s "$ACOWORK_ADB_SERIAL" shell getprop ro.build.version.release
```

- `id` 应为 `uid=2000(shell)`。**不是 2000 时先停下来**：本文档的 shell 档判据（尤其 §3 的 `fs:system` 不可达、§4 的拒绝理由）只在 system-shell 权限下成立。
- `getenforce` 应为 `Enforcing`。`Permissive` 意味着这台机器已经被人动过，判据要按 root 档（§6）重估。
- 序列号是设备标识，不要写进任何提交物。本仓库历史里曾有它，已重写；测试改用"形状检查"（`serial_shaped_token`）而不是记住具体值。

---

## A. 地面实况回放（不需要设备，先跑这个）

```sh
cargo test -q -p acowork-android --test device_ground_truth
```

**通过判据**：15 passed，0 failed。

这一步花 1 秒，能挡住最常见的回归：改了 `probe.rs`/`facts.rs` 之后，解析真实排版的能力悄悄坏了。它不需要手机，所以每次改完都该跑。

---

## B. 活设备验证

### 1. 建立宿主根目录

`--root` 目录承载 `settings.json`、快照、审计、证据四类文件，运行时会在里面建 `snapshots/`、`audit/`、`evidence/` 三个子目录。

```sh
mkdir -p host-run
acowork-host --root host-run "getprop ro.build.version.release"
```

**通过判据**（默认配置下）：

- 分类行显示 `ReadOnly`，覆盖能力是 `android:shell:read`；
- 退出码 0，输出是 Android 版本号（例如 `10`）；
- 打印了 `attempted` 与 `completed` 两条审计，且 `audit/` 目录下有对应文件；
- **没有**触发审批提问（只读自动放行是 §4.4 的规则，若这里问了人，就是 auto-pass 破了）。

### 2. 自定义配置：屏幕上的数字必须回到链上

写一份和默认值明显不同的 `host-run/settings.json`（字段名和默认值见 [android-runtime-settings.md](android-runtime-settings.md)，那 17 行由 `catalog.rs` 从代码生成；下面每个键都是目录里的真名，别照记忆写）：

```json
{
  "storage": { "snapshot_subdir": "snap", "audit_subdir": "log", "evidence_subdir": "ev" },
  "budgets": { "output_cap_bytes": 8192 },
  "timing": { "command_timeout_secs": 7, "lock_ttl_secs": 45, "bugreport_timeout_secs": 45 },
  "evidence": { "bugreport": false, "logcat_tail_lines": 200 },
  "capability_ceiling": ["android:shell:read"]
}
```

```sh
acowork-host --root host-run "getprop ro.build.version.release"
```

**通过判据**：

- 打印的超时/输出上限是 7 s 与 8 KiB，不是默认的 30 s / 1 MiB；
- 快照落在 `host-run/snap`、审计落在 `host-run/log`（子目录名生效）；
- 请求一个需要 `fs:outside-app` 的动作时，输出里出现 `off by settings: android:fs:outside-app`，而不是"设备不支持"。这两句话的区别是整套配置面的意义：**操作员关掉的**和**设备做不到的**不能长得一样。

### 3. 写 → 快照 → 恢复 round-trip（这一步是本项目的核心主张）

```sh
adb -s "$ACOWORK_ADB_SERIAL" shell 'echo ORIGINAL-BEFORE-RUNTIME > /data/local/tmp/acowork-demo.txt'

acowork-host --root host-run --yes \
  "echo REPLACED-BY-RUNTIME > /data/local/tmp/acowork-demo.txt"

adb -s "$ACOWORK_ADB_SERIAL" shell 'cat /data/local/tmp/acowork-demo.txt'
```

**通过判据**（四条都要满足，缺一条就是 bug）：

1. 分类行是 `FileWrite`，需要 `android:fs:outside-app`；
2. 执行后 `cat` 看到 `REPLACED-BY-RUNTIME`；
3. 退出前打印 `restore    1 undone, 0 failed, 0 left for another session`，且其下 `restored` 一行的目标就是 `acowork-demo.txt`——**审批上点名的文件必须等于快照删掉/改掉的**，这是"人批准的东西"和"东西被改的地方"之间的同一性；
4. restore 之后 `cat` 回到 `ORIGINAL-BEFORE-RUNTIME`，字节精确。用哈希确认，不要用肉眼：

```sh
adb -s "$ACOWORK_ADB_SERIAL" shell 'sha256sum /data/local/tmp/acowork-demo.txt'
```

期望值就是 `ORIGINAL-BEFORE-RUNTIME\n` 的 sha256（`printf 'ORIGINAL-BEFORE-RUNTIME\n' | sha256sum`）。

再测一次"新建后撤销"（原来不存在的路径）：

```sh
acowork-host --root host-run --yes "echo created > /data/local/tmp/acowork-new.txt"
adb -s "$ACOWORK_ADB_SERIAL" shell 'ls /data/local/tmp/acowork-new.txt'   # 应报 No such file
```

**通过判据**：打印形如 `restore    1 undone, 0 failed, 0 left for another session`，其下 `restored  /data/local/tmp/acowork-new.txt <absent>`——`<absent>` 表示恢复的目标状态是"本来就没有这个文件"。文件确实消失。

### 4. 拒绝路径：拒绝必须比执行更可靠

逐条跑，每条都应当**在碰设备之前**停下来：

```sh
acowork-host --root host-run --yes "settings put system font_scale 1.1"   # ceiling 只给了 read
acowork-host --root host-run --yes "toybox rm -fr /data/data/com.android.providers.telephony"
acowork-host --root host-run --yes "find /sdcard -name '*.log' -delete"
acowork-host --root host-run --yes "ping -c 1 8.8.8.8"
acowork-host --root host-run --yes "sh -c 'getprop ro.build.version.release'"
```

**通过判据**：

| 脚本 | 期望 |
|---|---|
| `settings put …` | 拒绝，理由点名 `android:shell:write` 未在设备声明中，并说明下一步该改哪个设置 |
| `rm -fr /data/data/…` | 判 `SystemWrite`，且理由里带"no app-data capability exists … (upstream review 37, B2)"——这句话是给人看的，说明这个档是**借来的**，不是设计成这样的 |
| `find … -delete` | 拒绝，理由点名是 `-delete` 这个动作，不是"find 不认识" |
| `ping` | 拒绝，理由说没有 egress 能力、**批准也不会解锁**（区别于"需要审批"） |
| `sh -c '…'` | 拒绝，理由说嵌套解释器里的命令分类器看不见 |

`ping` 那条判据值得单独强调：它必须说"approval will not unblock this"。如果它说"unanalysable/on neither list"，说明 egress 又掉回未知命令的兜底桶，把"没人授权过"伪装成"我看不懂"。

### 5. 损坏配置必须 fail-closed

```sh
printf '{"timing":{"command_timout_secs":7}}' > host-run/settings.json   # 故意拼错字段名
acowork-host --root host-run "getprop ro.build.version.release"
```

**通过判据**：报错指名出错的字段（`timing.command_timout_secs`），**不产生任何设备调用**，也不静默回默认值。看到版本号输出就是失败——静默采用默认值意味着操作员以为自己的 7 秒生效了。

测完记得把 `settings.json` 修回来。

---

## 6. root 档（等设备到位后）

前提：`adb shell id` 返回 `uid=0`，或 `su` 可用。先确认这一点，**不要靠猜**：

```sh
adb -s "$ACOWORK_ADB_SERIAL" shell 'id; getenforce; mount | head -3'
```

root 档新增的判据（shell 档测不到，因为那些能力根本不可达）：

1. **`fs:system` 可达性来自探测事实，不来自权限**。`HostProfile` 的 `system_remountable` 由 §2 item 7 的 `touch`/remount 实测决定；root 不等于可写（dm-verity 仍在）。判据：`acowork-host` 打印的声明能力里，`android:fs:system` 出现与否必须和 `mount -o remount /system` 能否成功一致。
2. **`ForeignRead` 是真审批**。`cat /data/data/com.android.providers.telephony/databases/mmssms.db` 应判 `ForeignRead`，需要 `fs:system`，且理由里带 B2 那句借用说明。设备状态不得改变——跑完 `sha256sum` 那个库文件应当不变。
3. **不可逆档要求回滚路径**。`fs:system` 在契约里标 `Irreversible`（没有 `/system` 的快照可恢复），所以写 `/system` 必须额外要一条人写下的回滚说明。判据：不提供回滚路径时请求被拒；提供后放行且这条说明进了审计。
4. **SELinux 单独门**。`setenforce 0` 判 `SelinuxChange` → `android:selinux:permissive`，与 `fs:system` 是两个能力，不得互相夹带。测完必须 `setenforce 1` 回来，并在审计里看到这两笔。
5. **证据源在 root 下才齐全**。`bugreportz`/`dumpsys` 这类源在非 root 上是"读不到"而不是"没配"。判据：`evidence/` 里每个产物的字节数与 digest 对得上，且被关掉的源（`evidence.bugreport: false` 这类）在 capture 时**一条命令都不发**，并返回 `NotAllowed` 而不是空结果——静默返回空会被调用方读成"这台机器没有日志"。
6. **`pm install` round-trip**：只在愿意装东西的设备上做（自己的测试机），不要装机主手机。判据：装完能 `pm list packages` 看到，卸载后 `pm dump` 无残留，全程审计。

root 档跑完，把 `settings.json` 的 `capability_ceiling` 收成只读再跑一遍 §1，确认"关掉高档之后设备退回 shell 档行为"这条也成立。

---

## 7. 判不过的时候

| 现象 | 先看哪里 |
|---|---|
| 只读命令被要求审批 | `Effect::is_read_only` 与 §4.4 auto-pass；再看该命令是否被 `has_unquoted_expansion` 撤了豁免 |
| 写命令没被快照 | 该档是否 `FileWrite`；`SnapshotStore` 的预算是否把这次快照挤掉（`budgets`） |
| restore 报 `0 undone` 但文件确实改了 | 审批点名的路径与快照记录的路径不一致——查 `written_targets` 的词法（引号、粘连 `-czf`、`>` 与 `>file`） |
| 拒绝理由说"设备不支持"但设备其实支持 | ceiling 与设备声明的合取在哪一层被算；"off by settings" 和"device cannot"必须分开 |
| 输出被截断 | `budgets.output_cap_bytes`（§2 已修：这个值以前只是装饰，现在真被消费） |
| 想快速看一批脚本的定档 | `cargo run -q -p acowork-android --example fxprobe < shapes.txt`（它是探照灯，不是测试；发现问题要落成回归测试） |

---

## 8. 一次完整通过的记录格式

跑完把这几项抄下来，它们是判断"这台设备支持到哪一档"的唯一凭据：

```text
设备型号 / Android 版本 / uid / getenforce
A. device_ground_truth: 15 passed
B1. ReadOnly 退出码与耗时
B2. 自定义数字是否回到链上（7s / 8KiB / snap / log / "off by settings"）
B3. round-trip：undone 计数、点名文件、restore 后 sha256
B4. 五条拒绝的原文
B5. 损坏配置的报错原文
（root 档）fs:system 可达性、ForeignRead、不可回滚拒绝、SELinux 两笔、证据 digest
```

新设备的第一次 B 轮跑完，产出的应当是**对分类器表的修改**（哪条命令的 usage 文本和 BLA-AL00 不同），而不是"测试通过"四个字。这个移植的表是按设备事实写的，换一台机器就是换一批事实。

# ADR-AND-003: 独立引擎与可配置 Runtime 拉起契约

- **状态**：Accepted
- **日期**：2026-11-17
- **相关**：[ADR-AND-001](ADR-AND-001-android-host-profiles-and-execution-backend.md)、[ADR-AND-002](ADR-AND-002-platform-contract-layer.md)、[开发就绪度评估](../../review/zh/2026-10-28-readiness-assessment.md) B3 / B6、上游 design 30、上游 `acowork-node` spawn 硬编码
- **实现**：`crates/acowork-android/src/node/`（引擎规格、进程表、能力 tag、enroll 形状）、`crates/acowork-android-cli` 的 `serve` / `runtime` 子命令

---

## 1. 背景

就绪度评估留下两条与「怎么和 Node 配合」直接相关的开放项：

| 编号 | 问题 |
|---|---|
| **B3** | Android 引擎是编进上游 `acowork-runtime`，还是独立引擎？ |
| **B6** | 上游 Node 用 `current_exe().parent().join("acowork-runtime")` 硬找兄弟二进制；本仓 CLI 叫 `acowork-android`，契约如何处理？ |

产品侧现已裁定，本 ADR 把裁定写成可执行的约束。

---

## 2. 决策

### 2.1 B3 → **独立引擎**（与 `acowork-runtime` 分开，独立发展）

Android 的 Node + Runtime **不**编进上游 `acowork-runtime`，**不** path/git 依赖上游 `acowork-node` / `acowork-runtime` crate 或二进制。

本仓库在内部实现 Android 侧的 Node 与 Runtime（可同二进制多子命令，也可拆进程），**唯一对外耦合是 Gateway 协议**：

- MQTT / HTTP 上的 enroll、NodeInfo、控制面命令、能力 tag 语义
- Runtime 对外暴露的 loopback HTTP 与实例身份约定

判据：换掉本仓实现，只要协议与 tag 语义不变，Gateway 与 Desktop/Mobile 客户端不必改。

> 这同时回答一个常见疑点：**「node+runtime 一体，是不是就不必依赖上游 node/runtime？」——是。**  
> 依赖上游二进制只会把 B6 的兄弟文件名耦合和 B3 的引擎归属一起带回来。一体实现守协议即可接入集群。

### 2.2 B6 → **Runtime 可配置；只在协议层约束，不在二进制名约束**

拉起 Runtime 的方式是配置项（`EngineSpec`），不是「与 node 二进制同目录且名叫 `acowork-runtime`」。

默认值（一体交付）：

```text
engine = <当前可执行文件>
args   = ["runtime", …协议所需参数…]
```

也允许指向任意可执行文件，只要它接受同一套**协议形参**（`--agent-id`、`--agent-instance-id`、`--http-port`、`--gateway-host`、`--node-id`、…）。

**禁止**：把「文件名必须是 `acowork-runtime`」写进本仓任何生产路径。回收/巡检按进程表与实例 id 认孩子，不按 argv0 基名认孩子。

### 2.3 进程角色（一体二进制下的两个角色）

| 角色 | CLI 入口 | 职责 |
|---|---|---|
| **Node** | `acowork-android serve` | 探测宿主、MQTT enroll、NodeInfo/NodeReady、`:19900` 反代、进程表、控制面 ping/start/stop |
| **Runtime** | `acowork-android runtime`（或配置的外部引擎） | 单个 agent 实例：宿主执行链 + loopback HTTP；（后续）LLM 主循环 |

同一文件、两种角色；root-shell 仍是宿主探测出来的**模式**，不是第三角色。

### 2.4 与 Gateway 的边界

- **上报**：能力摘要走 ADR-AND-001 §7.1 的 tag 词表（`android:host-profile:…`、`android:cap:…` 等），装进协议的 `capabilities: repeated string`。
- **enroll**：payload **形状**对齐上游 `NodeEnroll` / `NodeInfo` 字段语义；本仓自建编解码与客户端，不链接 `acowork-core`。
- **控制面命令**：Node 理解「安装 / 启动 / 停止 agent」等协议动词后，用本地 `ProcessTable` + `EngineSpec` 执行——动词来自协议，exec 路径来自配置。

---

## 3. 后果

**正面**

- B3 / B6 关闭；Android 发布节奏与上游桌面引擎解耦。
- 一体二进制适合 Termux / 调试机；外部引擎路径留给测试替身与未来拆分。
- 零上游 node/runtime 依赖与 ADR-AND-002 的结构保证一致。

**负面 / 承担**

- 必须自建（或后续增量）MQTT enroll 与控制面客户端；不能「顺便」用上游 crate。
- 协议字段演进时，本仓要自己追齐——用契约测试钉 tag 与 enroll 形状，而不是钉上游类型名。

**不做**

- 不把本仓打成上游 `acowork-runtime` 的 feature。
- 不在回收逻辑里扫描 `acowork-runtime` 字符串当唯一判据。

---

## 4. 验证

| 项 | 方式 |
|---|---|
| 默认一体拉起 | `serve` 用 `current_exe()` + `runtime` 子命令 spawn，进程表能 list/stop |
| 外部引擎 | `--engine /path/to/stub` 可替换，不要求文件名 |
| 能力 tag | `node::capability_tags(profile)` 快照测试，不含设备序列号 / 路径 |
| 与上游二进制无关 | `cargo tree -p acowork-android-cli` 无 `acowork-node` / `acowork-runtime` |
| MQTT enroll | 本地 `proto/node_control.proto` + rumqttc；`DataEnvelope` field 号对齐上游；enroll_result 落 `identity.json` |
| 反代 | `:19900` `/health`（开放）+ `/fs/browse` + `/agents/{id}/*`（headers+body 转发；`X-ACowork-Node-Token` 门禁） |
| 包库存 | `install`(local_path) / `uninstall` → `installed.json` + retained `InstalledAgentInfo`；`package_url` 暂 `not_implemented` |
| MQTT 重连 | soft-restart 清 ready → 新 EventLoop → ConnAck 后 bootstrap 通道触发 re-announce |

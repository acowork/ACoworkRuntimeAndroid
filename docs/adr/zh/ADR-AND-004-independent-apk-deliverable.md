# ADR-AND-004: APK 交付物独立于上游 mobile

- **状态**：Accepted
- **日期**：2026-11-18
- **相关**：[ADR-AND-003](ADR-AND-003-independent-engine-and-spawn-contract.md)、[就绪度评估 B4](../../review/zh/2026-10-28-readiness-assessment.md)
- **实现**：规划中的 `apps/android`（`acowork-android-app`）；与 `crates/acowork-android-cli` 并列的第二交付物

---

## 1. 背景

就绪度评估 **B4** 曾把本仓库 APK 与主仓 `apps/acowork-mobile` 写成「形态撞车、归属未裁定」。

产品澄清后，二者**用途本就不重叠**：

| | 主仓 `acowork-mobile` | 本仓 `acowork-android-app` |
|---|---|---|
| 层级 | **客户端**（与 desktop 同等地位） | **宿主**（Node + Runtime） |
| Runtime | **无** | 有（本仓引擎） |
| 角色 | 用户用来对话 / 控制集群的 App | 手机上跑 Agent 实例、向 Gateway 注册的节点 |

「撞车」是误判；无需与 mobile 合并或长 host mode。

---

## 2. 决策

1. **本仓库独立于主仓**（与 ADR-AND-003 一致）：不 path/git 依赖上游 node/runtime；协议对齐 Gateway 即可。
2. **`acowork-android`（CLI）与 `acowork-android-app`（APK）都是本仓交付物**，共享本仓库；不依赖、不合并主仓 mobile。
3. **B4 关闭**：主仓 mobile 是客户端，本仓 APK 是宿主——并列存在合理，互不替代。
4. 主仓 NDK/Tauri 管线**可作参考，非前置条件**；本仓自建 Gradle + JNI/FFI 外壳。

---

## 3. 后果

**正面**

- APK roadmap #4 解除阻塞，可与 CLI 并行推进。
- 拓扑对齐主仓：Gateway ← 宿主（desktop node/runtime **或** 本仓 CLI/APK）← 客户端（desktop UI **或** mobile）。

**承担**

- 自建前台服务、保活、scoped storage、电池白名单与发布签名。
- 不把「复用 mobile 工程」当作默认路径。

---

## 4. 验证

| 项 | 方式 |
|---|---|
| 文档无 B4 阻塞 | README roadmap #4 不再标 ⛔；评估 B4 标 Closed |
| 工程独立 | `apps/`（或等价路径）不引用上游 `acowork-mobile` 包名 |
| 与 CLI 共享引擎 | APK 通过本仓 `acowork-android`（及后续 FFI）调用同一 Node/Runtime 语义 |

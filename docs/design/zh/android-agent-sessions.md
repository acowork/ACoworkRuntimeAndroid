# Agent 详情页：会话历史列表（APK 形态）

> 状态：已实现（[`AgentDetailActivity`](../../../apps/android/app/src/main/java/com/acowork/androidhost/AgentDetailActivity.kt)、
> [`AgentSession.kt`](../../../apps/android/app/src/main/java/com/acowork/androidhost/AgentSession.kt)）。
> 关联：[ADR-AND-004](../../adr/zh/ADR-AND-004-independent-apk-deliverable.md) §1（宿主 ≠ 客户端）、
> [android-runtime-settings.md](android-runtime-settings.md)（本 app 的界面定位）。
> 日期：2026-11-19

## 0. 问题在哪

Agents 页只列了「装了哪些 agent」——名字、包名、运行状态。点不进去，所以**手机上唯一一份
关于某个 agent 实际干了什么的证据**（会话记录）在界面上不可见。上层（desktop 客户端）能看，
手机这台机器的主人不能看，而会话数据就在他自己的设备上。

这一页补的就是这个缺口：**一级页回答"有什么"，二级页回答"它干过什么"。**

## 1. 界面定位没有变

[android-runtime-settings.md](android-runtime-settings.md) §0 的结论仍然成立：这个 APK 是运维面板，
不是产品界面。所以本页**只读**——不新建会话、不打开发送、不删除、不改名。理由不是"来不及做"，
而是**这些动作的归属是客户端 + Runtime**：会话的写路径是 `POST /sessions/{sid}/messages`，
删除是 `DELETE /sessions/{id}`，两者都要经过 Gateway 鉴权与 ADR-076 的 read/write 规则。
在宿主面板上复制一套，就多出第二条写路径和第二个权限判定点。运维面板看证据即可。

## 2. 数据从哪来（本节是唯一有分量的决策）

三个候选：

| 来源 | 能拿到什么 | 为什么不用 / 用 |
|---|---|---|
| Runtime HTTP `GET /sessions`（desktop 客户端走这条） | 与 desktop 完全一致的 `SessionInfo` | ❌ agent 没在跑时拿不到。Node 只为 Gateway 启动过的 agent 保留 loopback 端口（`PortTable`，在 FFI 进程内，UI 不在同一条链上），而本页必须在 agent **停着**的时候也能回答"这机器上跑过什么" |
| 扫 `{work_dir}/conversations/*.jsonl` | 有文件 == 有过会话；消息条数可数 | ❌ 没有标题（标题在 meta 里），且要自己实现"哪一行算一条消息"，是第二份业务逻辑 |
| 只读查询 `{work_dir}/memory/private.sqlite` 的 `sessions` 表 | `title` / `created_at` / `last_active_at` / `message_count` | ✅ 与运行时回答问题时用的**同一个**真相源（`SqliteSessionMetaStore` 之上的 `list_recent`），agent 停着也在，读不到就报错 |

**代价写清楚**：这条路径让 UI 知道了存储布局（表名、列名、排序键），即一份隐式契约。
收敛手段是把它**关在一个文件里**（`AgentSessions`），列清单与 `ORDER BY` 都在那一处，
并且它只读——布局变化时坏的是一页列表，不是数据。

运行中的 Runtime 同时写这个库，所以连接按 WAL 语义打开：先试 `OPEN_READONLY`，
平台不允许只读 attach WAL 索引时退到 `OPEN_READWRITE`（仍然不带 `CREATE`），
两种情况下本 app 都不发任何写语句。

## 3. 排序与字段：对齐 desktop，一处刻意不同

| 项 | desktop `SessionPanel` | 本页 |
|---|---|---|
| 顺序 | `last_active_at DESC`（store 的 `list_recent`） | 同 |
| 标题 | `title`，空则 `Untitled session` | 同 |
| 消息数 | `N msg` | 同 |
| 相对时间 | `created_at` | **`last_active_at`** |

最后一行是唯一偏离：列表按最近活动排序，却显示创建时间，在手机上会出现"3 天前"排在
"1 小时前"上面——排序依据与可见依据不一致，用户只能当作乱序。所以这一页显示的相对时间
就是排序用的那个时间（"最近活动"）。desktop 的排序规则不变，两端的**行顺序仍然一致**。

分桶阈值（<1 分 `just now`、<1 小时 `N min ago`、<1 天 `N h ago`、<30 天 `N days ago`、
更早显示日期）与 desktop 的 `formatRelativeTime` 相同；这部分是纯函数
（[`SessionTimes`](../../../apps/android/app/src/main/java/com/acowork/androidhost/SessionTimes.kt)），
有 JVM 单测覆盖边界与时钟倒流。

## 4. 三种状态，缺一不可

| 状态 | 显示 | 为什么必须区分 |
|---|---|---|
| 有会话 | 列表 + 底部 `N sessions` | —— |
| 库在但没行 / 库还没生成 | 居中 `No sessions yet. This agent has not chatted on this phone.` | 新装的 agent 就该长这样，不是错误 |
| 库在但读不出来 | 居中 `Cannot read the session store: <原因>`，可选中复制 | "我没看到"和"没有"是两个答案；把读失败显示成空列表，等于替设备撒谎 |

外加一种身份状态：agent 已被卸载但目录还在（`installed.json` 里没有它）时，头部显示
`<instanceId> · not installed`，会话照常读——磁盘上的证据比库存表更耐时间。

## 5. 视觉沿用，不新起一套

- 没有 `Toolbar`：本 app 从来没有 app bar，为一个页面引入会变成第二套骨架。头部是
  `[←] + 24sp bold 标题`，与 Agents/Settings 的标题同一套边距节奏（20dp）。
- 行样式复用 `item_agent` 的度量：16dp 横向内边距、64dp 最小行高、16sp 主文本 + 13sp 次级灰、
  `DividerItemDecoration` 分隔线。
- 汇总行 + `Refresh` 按钮放在列表下方，与 Agents 页同样的位置和同样的 outlined 按钮。
- 二级页不显示底部导航：drill-down 的返回由系统返回键 + 左上箭头承担。

## 6. 非目标

- 分页 / 搜索：行数上限 `MAX_ROWS = 200`（一屏一瞥，不是档案库）。真需要翻历史时，那说明
  该在 desktop 上做。
- 会话详情、重命名、删除（见 §1）。
- 显示"正在流式输出"的绿点：那需要 Runtime 的实时状态；本页读的是落盘状态，
  编一个出来等于谎报。

## 7. 验证

| 项 | 方式 | 结果 |
|---|---|---|
| 顺序 / 空标题 / 条数（SQL 层面） | 真机拉取的 `private.sqlite` 上跑同一条 SQL，插入两行构造排序 | `last_active_at DESC`，NULL 标题保留 |
| 相对时间分桶 | `:app:testDebugUnitTest`（7 个用例，含边界与未来时间） | 通过 |
| 点行进二级页 | 真机点 Agents 行 → 详情页 | 标题/包名/`Stopped` 正确 |
| 真实数据 | 真机三个已装 agent | `查一下明天的天气 · 2 h ago · 253 msg`、`Untitled session · 4 h ago · 0 msg` |
| 空态 | 临时把该 agent 的 `memory/` 改名后点 Refresh，随后立刻还原 | 显示 `No sessions yet…`；还原后 Refresh 恢复正常 |
| 返回 | 点左上箭头 | 回到 Agents 页 |
| 构建 | `:app:assembleDebug` | 通过 |
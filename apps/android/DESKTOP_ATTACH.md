# 把手机 Node 挂到 Gateway（真实场景 = 局域网）

手机上**优先粘贴 Desktop 的 enroll 码**（一整段，含 Gateway + token）。无摄像头设备也走这条路；扫码只是可选。

Dial-back（Gateway 回连手机反代）由 App **自动取 Wi‑Fi IPv4:19900**，界面不出现 advertise，也**不要**填 `127.0.0.1`。

---

## 步骤

1. 手机与 PC 路由互通（PC 能 ping 手机 IP 即可）
2. PC 上 Gateway 正常
3. Desktop 左侧栏底部 **`+`** → **「在其他机器启动 Node」**（和「启动本机 Node」并列，本机已有 Node 也能开）
   - 把 **Gateway 主机** 改成手机可达的局域网 IP（例如 `192.168.17.113`，不要用 `127.0.0.1`）
   - 扫弹窗里的二维码，或点 **「复制 enroll 码」**
4. 手机 Host App：
   - 点 **「Paste enroll code」**（或把整段粘进 Token 框）→ Gateway / Token 自动填好
   - Name = 可选
   - Start
5. Status 应有 `"enrolled":true` 且 `http_endpoint` 为手机 Wi‑Fi IP:`19900`
6. Desktop **刷新** Nodes，应出现该 Node；再对它 Install / Start agent

若以前已经用空 Token 注册过：Stop → 粘新 enroll 码 → Start 再 enroll 一次（会 `put_if_absent` 绑 owner）。仍没有的话清 App 数据后重装 token 再 Start。

**不要**再开 `adb reverse` / `adb forward`。

---

## 自检

```powershell
# PC → 手机反代
curl http://192.168.18.40:19900/health
# 期望 {"ok":true,"role":"node"}

# 桌面 Node 仍在本机
curl http://127.0.0.1:19900/health
```

adb 快速启动：

```powershell
adb shell am broadcast -n com.acowork.androidhost/.HostDebugReceiver `
  -a com.acowork.androidhost.DEBUG --es cmd start `
  --es gateway http://192.168.17.113:19876 --es name apk-phone
adb logcat -d | findstr ACoworkHost
```

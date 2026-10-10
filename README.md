# 全聚合 VST 直播地址（网页版）

「全聚合」（com.vlive.vst 2.1.2）APK 逆向结果的静态展示站：全部直播接口、
服务器节点（HTTPS + UDP/P2P）、本地代理地址与实测记录。
数据在 `data.json`，改数据刷新页面即可，无构建步骤。

结论一句话：APK 内没有内置任何单频道 m3u8，直播频道由这些服务器接口
在授权码登录（sessionid）后动态下发。

## Cloudflare Pages 部署

本仓库连接 Cloudflare Pages 时使用以下设置：

- Framework preset：**None**
- Build command：**（留空）**
- Build output directory：**/**
- Production branch：**main**

连接步骤：Cloudflare 控制台 → Workers & Pages → Create → Pages →
Connect to Git → 选择本仓库 → 按上面设置保存并部署。
之后每次 push 到 main 分支都会自动重新部署。

## 本地预览

```bash
python3 -m http.server 8000
# 打开 http://localhost:8000
```

（直接双击 index.html 会因浏览器限制读不到 data.json，需用本地服务器。）

## 文件

- `index.html` / `style.css` / `app.js` — 页面与交互（搜索、单条/全部复制）
- `data.json` — 全部地址数据（源头：APK 静态逆向 + DNS TXT txt.vstvip.us 实查解码，2026-10-10）

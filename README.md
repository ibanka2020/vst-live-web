# 全聚合 VST 网页版

「全聚合」（com.vlive.vst 2.1.2）的网页版：界面与流程仿 APK，使用与 APK
完全相同的服务器节点、登录方式和数据接口，支持**点播**和**直播**。
纯静态站（无构建步骤），为 Cloudflare Pages 的 Git 连接部署准备。

## 功能（对照 APK）

- **登录（LoginActivity）**：输入授权码，按 APK 的原算法派生 sessionid——
  设备信息 JSON → GZIP → AES/CBC/PKCS7 加密（密钥由静态串的 MD5 派生），
  再逐个节点请求 `/v6/test.json` 测速选优。算法已与 APK 交叉验证：
  网页生成的 sessionid 用 APK 的密钥解密可还原同一 JSON。
- **点播（HomeActivity / VodActivity）**：拉取 `{节点}/api/v3/json`
  （回退 `/api/v2/api`）配置，站点切换、分类、分页、海报墙、搜索，
  详情页含线路/选集，历史与收藏存浏览器本地。
- **直播（LiveActivity）**：拉取 `{节点}/api/v3/live`，兼容 JSON / M3U /
  TXT 三种频道表格式和 FongMi 的 lives 型配置；频道若只给 id，
  按 APK 的方式请求 `/api/v3/liveids`（头带 sessionid/language/chid，
  响应按 “TV” 编码解开）换播放地址。播放器支持 HLS（hls.js）与原生直链。
- **设置**：节点与登录信息查看、CORS 代理前缀、退出登录、清数据。

## 浏览器与 APK 的固有差异

- 节点服务器若未开启 CORS，浏览器会拦截直连（APK 不受此限制）。
  遇到加载失败，可在「设置」里填一个你信任的 CORS 代理前缀再试。
- 走 TVBus/UDP P2P 的频道流（liveids 返回 uuid 的频道）浏览器无法拉取，
  页面会明确提示，这类频道请在 APK 里看。
- 设备的 ChipId 等硬件字段浏览器取不到，用本地持久化的随机标识代替。

## Cloudflare Pages 部署

- Framework preset：**None**
- Build command：**（留空）**
- Build output directory：**/**
- Production branch：**main**

每次 push 到 main 分支都会自动重新部署。

## 本地预览

```bash
python3 -m http.server 8000
# 打开 http://localhost:8000
```

（直接双击 index.html 会因浏览器限制读不到 data.json，需用本地服务器。）

## 文件

- `index.html` / `style.css` / `app.js` — 页面、样式与全部逻辑
- `data.json` — 逆向得到的节点/接口数据（源头见仓库外报告，2026-10-10 实查）

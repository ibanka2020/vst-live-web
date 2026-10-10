// 自建 CORS 代理（Cloudflare Worker）
// 部署：Cloudflare 控制台 → Workers & Pages → Create Worker → 粘贴本文件 → Deploy
// 部署后把下面这个地址填到网页版「设置 → CORS 代理前缀」里：
//   https://<你的 Worker 域名>/?url=
// 例如 https://vst-proxy.xxxx.workers.dev/?url=
//
// 作用：给响应补上 Access-Control-Allow-Origin，并转发 sessionid 等请求头
// （公共代理大多会丢弃自定义请求头，登录和 liveids 换址会失败，所以推荐自建）。
export default {
  async fetch(request) {
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': request.headers.get('Access-Control-Request-Headers') || '*',
      'Access-Control-Max-Age': '86400'
    };
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    const target = new URL(request.url).searchParams.get('url');
    if (!target) return new Response('missing ?url=', { status: 400, headers: cors });
    let t;
    try { t = new URL(target); } catch (e) { return new Response('bad url', { status: 400, headers: cors }); }
    if (!/^https?:$/.test(t.protocol)) return new Response('only http/https', { status: 403, headers: cors });

    const headers = new Headers();
    for (const h of ['sessionid', 'language', 'chid', 'authorization', 'content-type', 'range']) {
      const v = request.headers.get(h);
      if (v) headers.set(h, v);
    }
    let resp;
    try {
      resp = await fetch(t.toString(), {
        method: request.method,
        headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        redirect: 'follow'
      });
    } catch (e) {
      return new Response('proxy fetch failed: ' + e.message, { status: 502, headers: cors });
    }
    const out = new Headers(resp.headers);
    for (const [k, v] of Object.entries(cors)) out.set(k, v);
    out.delete('content-security-policy');
    return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: out });
  }
};

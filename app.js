let DATA = null;

function row(url, desc) {
  const div = document.createElement('div');
  div.className = 'row';
  div.dataset.text = (url + ' ' + (desc || '')).toLowerCase();
  const code = document.createElement('code');
  code.textContent = url;
  if (desc) {
    const d = document.createElement('span');
    d.className = 'desc';
    d.textContent = desc;
    code.appendChild(document.createElement('br'));
    code.appendChild(d);
  }
  const btn = document.createElement('button');
  btn.className = 'copy';
  btn.type = 'button';
  btn.textContent = '复制';
  btn.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(url); } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = url; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); ta.remove();
    }
    btn.textContent = '已复制';
    btn.classList.add('done');
    setTimeout(() => { btn.textContent = '复制'; btn.classList.remove('done'); }, 1500);
  });
  div.appendChild(code);
  div.appendChild(btn);
  return div;
}

function section(title, rows) {
  const s = document.createElement('section');
  const h = document.createElement('h2');
  h.textContent = title;
  s.appendChild(h);
  rows.forEach(r => s.appendChild(r));
  return s;
}

function render(data) {
  DATA = data;
  const app = document.getElementById('app');
  app.innerHTML = '';

  const liveRows = [];
  data.httpsNodes.forEach(n => data.liveEndpoints.forEach(ep =>
    liveRows.push(row(n + ep.path, ep.desc))));
  app.appendChild(section('直播接口（节点 × 接口）', liveRows));

  app.appendChild(section('HTTPS 服务器节点',
    data.httpsNodes.map(n => row(n, '直播/VOD 配置节点，登录时用 /v6/test.json 测速选优'))));
  app.appendChild(section('UDP / P2P 节点（mesh / TVBus）',
    data.udpNodes.map(n => row(n, 'P2P 接入节点，频道媒体流经此拉取'))));
  app.appendChild(section('本地地址（App 内部）',
    data.localEndpoints.map(e => row(e.url, e.desc))));
  app.appendChild(section('同一批服务器上的相关接口',
    data.relatedEndpoints.map(e => row(e.path, e.desc + '（拼在任一节点基地址后）'))));

  document.getElementById('stat-nodes').textContent =
    data.httpsNodes.length + data.udpNodes.length;
  document.getElementById('stat-live').textContent =
    data.httpsNodes.length * data.liveEndpoints.length;
}

document.getElementById('search').addEventListener('input', e => {
  const q = e.target.value.trim().toLowerCase();
  document.querySelectorAll('.row').forEach(r => {
    r.style.display = !q || r.dataset.text.includes(q) ? '' : 'none';
  });
  document.querySelectorAll('section').forEach(s => {
    const visible = [...s.querySelectorAll('.row')].some(r => r.style.display !== 'none');
    s.style.display = visible ? '' : 'none';
  });
});

document.getElementById('copy-all').addEventListener('click', async (e) => {
  if (!DATA) return;
  const all = DATA.httpsNodes.flatMap(n => DATA.liveEndpoints.map(ep => n + ep.path)).join('\n');
  try { await navigator.clipboard.writeText(all); } catch (err) {}
  e.target.textContent = '已复制全部';
  setTimeout(() => { e.target.textContent = '复制全部直播接口'; }, 1500);
});

fetch('data.json')
  .then(r => r.json())
  .then(render)
  .catch(() => {
    document.getElementById('app').innerHTML = '<p class="empty">data.json 加载失败</p>';
  });

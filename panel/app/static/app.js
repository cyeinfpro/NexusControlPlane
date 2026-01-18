async function api(url, method = 'GET', body = null) {
  const opt = { method, headers: {} };
  if (body) {
    opt.headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
    opt.body = new URLSearchParams(body).toString();
  }
  const r = await fetch(url, opt);
  if (!r.ok) {
    const t = await r.text();
    throw new Error(t || ('HTTP ' + r.status));
  }
  const ct = r.headers.get('content-type') || '';
  if (ct.includes('application/json')) return await r.json();
  return await r.text();
}

async function addNode(ev) {
  ev.preventDefault();
  const f = ev.target;
  try {
    await api('/api/nodes', 'POST', {
      name: f.name.value,
      base_url: f.base_url.value,
      token: f.token.value,
    });
    location.reload();
  } catch (e) {
    alert('添加失败：' + e.message);
  }
  return false;
}

async function deleteNode(id) {
  if (!confirm('确认删除该节点？')) return;
  try {
    await api('/api/nodes/' + id, 'DELETE');
    location.reload();
  } catch (e) {
    alert('删除失败：' + e.message);
  }
}

async function createPair(ev) {
  ev.preventDefault();
  const f = ev.target;
  try {
    const data = await api('/api/pairs/create', 'POST', {
      host: f.host.value,
      path: f.path.value,
      sni: f.sni.value,
      insecure: f.insecure.checked ? '1' : '0',
      ttl_minutes: f.ttl_minutes.value || '1440',
    });
    const box = document.getElementById('pair-result');
    box.textContent = '配对码：' + data.code + '\n' +
      'Host：' + data.host + '\n' +
      'Path：' + data.path + '\n' +
      'SNI：' + data.sni + '\n' +
      'Insecure：' + (data.insecure ? 'true' : 'false');
    box.style.display = 'block';
  } catch (e) {
    alert('生成失败：' + e.message);
  }
  return false;
}

async function fetchNodeStatus(id) {
  const box = document.getElementById('node-status');
  box.textContent = '读取中...';
  try {
    const data = await api('/api/nodes/' + id + '/status');
    box.textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    box.textContent = '失败：' + e.message;
  }
}

async function fetchNodeRules(id) {
  const box = document.getElementById('rules-box');
  box.textContent = '读取中...';
  try {
    const data = await api('/api/nodes/' + id + '/rules');
    box.textContent = JSON.stringify(data, null, 2);
  } catch (e) {
    box.textContent = '失败：' + e.message;
  }
}

async function addRule(ev, nodeId) {
  ev.preventDefault();
  const f = ev.target;
  try {
    const payload = {
      mode: f.mode.value,
      local_port: f.local_port.value,
      targets: f.targets.value,
      wss_host: f.wss_host.value,
      wss_path: f.wss_path.value,
      wss_sni: f.wss_sni.value,
      wss_insecure: f.wss_insecure.checked ? '1' : '0',
      pair_code: f.pair_code.value,
    };
    await api('/api/nodes/' + nodeId + '/rules', 'POST', payload);
    fetchNodeRules(nodeId);
  } catch (e) {
    alert('添加失败：' + e.message);
  }
  return false;
}

async function fillWssFromCode(inputEl) {
  const code = inputEl.value.trim();
  if (!code) return;
  try {
    const data = await api('/api/pairs/' + encodeURIComponent(code));
    const f = inputEl.closest('form');
    f.wss_host.value = data.host || '';
    f.wss_path.value = data.path || '';
    f.wss_sni.value = data.sni || '';
    f.wss_insecure.checked = !!data.insecure;
  } catch (e) {
    // ignore
  }
}

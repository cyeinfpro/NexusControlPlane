(function(){
  const $ = (sel)=>document.querySelector(sel);
  const $$ = (sel)=>Array.from(document.querySelectorAll(sel));

  async function api(url, opts={}){
    const res = await fetch(url, Object.assign({headers:{'Accept':'application/json'}}, opts));
    const data = await res.json().catch(()=>({ok:false,error:'bad json'}));
    if(!res.ok){
      const msg = data && (data.detail || data.error) ? (data.detail || data.error) : ('HTTP '+res.status);
      throw new Error(msg);
    }
    return data;
  }

  function pill(ok){
    if(ok === true) return '<span class="pill ok">在线</span>';
    if(ok === false) return '<span class="pill bad">离线</span>';
    return '<span class="pill warn">未知</span>';
  }

  function escapeHtml(s){
    return String(s||'').replace(/[&<>"']/g,(c)=>({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
  }

  async function loadIndex(){
    const box = $('#nodes');
    if(!box) return;
    try{
      const r = await api('/api/nodes');
      const items = r.nodes.map(({node,status})=>{
        const online = !!status.ok;
        const realm = status.realm_running ? '<span class="pill ok">Realm 运行</span>' : '<span class="pill bad">Realm 停止</span>';
        const ruleCount = status.rule_count ?? '-';
        const connTotal = status.connections ? Object.values(status.connections).reduce((a,b)=>a+(b||0),0) : '-';
        return `
          <div class="item">
            <div class="row between">
              <div>
                <div style="font-weight:700;">${escapeHtml(node.name)}</div>
                <div class="muted small">${escapeHtml(node.base_url)}</div>
              </div>
              <div class="row gap">
                ${pill(online)}
                ${realm}
                <span class="pill">规则:${ruleCount}</span>
                <span class="pill">连接:${connTotal}</span>
                <a class="btn" href="/node/${node.id}">进入</a>
              </div>
            </div>
          </div>`;
      }).join('');
      box.innerHTML = items || '<div class="muted">暂无节点</div>';
    }catch(e){
      box.innerHTML = `<div class="alert">加载失败：${escapeHtml(e.message)}</div>`;
    }
  }

  async function loadNode(nodeId){
    await refreshNode(nodeId);
    await refreshRules(nodeId);
  }

  async function refreshNode(nodeId){
    const box = $('#node-status');
    if(!box) return;
    try{
      const st = await api(`/api/node/${nodeId}/status`);
      const online = !!st.ok;
      const realm = st.realm_running ? '运行' : '停止';
      const ruleCount = st.rule_count ?? 0;
      const conn = st.connections || {};
      const connTotal = Object.values(conn).reduce((a,b)=>a+(b||0),0);
      box.innerHTML = `
        <div class="stat"><div class="t">在线</div><div class="v">${online?'是':'否'}</div></div>
        <div class="stat"><div class="t">Realm</div><div class="v">${realm}</div></div>
        <div class="stat"><div class="t">规则数</div><div class="v">${ruleCount}</div></div>
        <div class="stat"><div class="t">总连接</div><div class="v">${connTotal}</div></div>
      `;
    }catch(e){
      box.innerHTML = `<div class="alert">状态获取失败：${escapeHtml(e.message)}</div>`;
    }
  }

  function ruleModeText(m){
    if(m==='wss_send') return 'WSS发送';
    if(m==='wss_recv') return 'WSS接收';
    return 'TCP/UDP';
  }

  async function refreshRules(nodeId){
    const box = $('#rules');
    if(!box) return;
    try{
      const rules = await api(`/api/node/${nodeId}/rules`);
      const list = (rules || []).map(r=>{
        const paused = !!r.paused;
        const state = paused ? '<span class="pill warn">暂停</span>' : '<span class="pill ok">运行</span>';
        const targets = (r.targets||[]).map(t=>`<div class="muted small">→ ${escapeHtml(t)}</div>`).join('');
        return `
          <div class="item">
            <div class="row between">
              <div>
                <div style="font-weight:700;">端口 ${r.local_port} <span class="pill">${ruleModeText(r.mode)}</span> <span class="pill">${escapeHtml(r.protocol)}</span></div>
                ${targets || '<div class="muted small">(无目标)</div>'}
              </div>
              <div class="row gap">
                ${state}
                <button class="btn" onclick="panel.pause('${r.id}', ${paused? 'false':'true'})">${paused?'恢复':'暂停'}</button>
                <button class="btn danger" onclick="panel.del('${r.id}')">删除</button>
              </div>
            </div>
          </div>`;
      }).join('');
      box.innerHTML = list || '<div class="muted">暂无规则</div>';
    }catch(e){
      box.innerHTML = `<div class="alert">规则获取失败：${escapeHtml(e.message)}</div>`;
    }
  }

  function showModal(){ $('#modal')?.classList.remove('hidden'); }
  function hideModal(){ $('#modal')?.classList.add('hidden'); }

  function onModeChange(v){
    const wssBox = $('#wss-box');
    const recvExtra = $('#wss-recv-extra');
    if(!wssBox) return;
    if(v==='wss_send' || v==='wss_recv') wssBox.classList.remove('hidden');
    else wssBox.classList.add('hidden');
    if(v==='wss_recv') recvExtra?.classList.remove('hidden');
    else recvExtra?.classList.add('hidden');
  }

  async function apply(nodeId){
    try{
      await api(`/api/node/${nodeId}/apply`, {method:'POST'});
      alert('已应用配置并重启 Realm');
      await refreshNode(nodeId);
      await refreshRules(nodeId);
    }catch(e){
      alert('应用失败：'+e.message);
    }
  }

  async function pauseRule(rid, paused){
    const nodeId = window.PAGE?.nodeId;
    try{
      await api(`/api/node/${nodeId}/rule/${rid}/pause?paused=${paused}`, {method:'POST'});
      await refreshRules(nodeId);
    }catch(e){
      alert('操作失败：'+e.message);
    }
  }

  async function delRule(rid){
    const nodeId = window.PAGE?.nodeId;
    if(!confirm('确认删除规则？')) return;
    try{
      await api(`/api/node/${nodeId}/rule/${rid}`, {method:'DELETE'});
      await refreshRules(nodeId);
    }catch(e){
      alert('删除失败：'+e.message);
    }
  }

  async function showLogs(nodeId){
    try{
      const r = await api(`/api/node/${nodeId}/logs?lines=200`);
      $('#logs').textContent = r.logs || '';
      $('#logmodal').classList.remove('hidden');
    }catch(e){
      alert('日志获取失败：'+e.message);
    }
  }

  function hideLogs(){ $('#logmodal')?.classList.add('hidden'); }

  async function handleAddRuleForm(){
    const form = $('#rule-form');
    if(!form) return;
    const nodeId = window.PAGE?.nodeId;
    form.addEventListener('submit', async (ev)=>{
      ev.preventDefault();
      const fd = new FormData(form);
      try{
        const res = await fetch(`/api/node/${nodeId}/rule`, {method:'POST', body:fd});
        const data = await res.json().catch(()=>({}));
        if(!res.ok){
          throw new Error((data && (data.detail || data.error)) || '创建失败');
        }
        if(data.pairing_code){
          alert('创建成功！\n\n接收端配对码：'+data.pairing_code+'\n\n（用于发送端自动获取 WSS 参数）');
        }else{
          alert('创建成功！');
        }
        hideModal();
        form.reset();
        onModeChange('tcp_udp');
        await refreshRules(nodeId);
        await refreshNode(nodeId);
      }catch(e){
        alert('创建失败：'+e.message);
      }
    });
  }

  // public API
  window.panel = {
    refreshNode, refreshRules,
    showAddRule: ()=>{ showModal(); },
    hideModal,
    onModeChange,
    apply,
    pause: pauseRule,
    del: delRule,
    showLogs, hideLogs,
  };

  // boot
  document.addEventListener('DOMContentLoaded', async ()=>{
    if(window.PAGE?.type==='index'){
      await loadIndex();
      setInterval(loadIndex, 4000);
    }
    if(window.PAGE?.type==='node'){
      const nodeId = window.PAGE.nodeId;
      await loadNode(nodeId);
      setInterval(()=>refreshNode(nodeId), 4000);
      setInterval(()=>refreshRules(nodeId), 5000);
      await handleAddRuleForm();
      onModeChange('tcp_udp');
    }
  });
})();

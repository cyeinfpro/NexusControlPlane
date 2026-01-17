function qs(sel, el=document){return el.querySelector(sel)}
function qsa(sel, el=document){return Array.from(el.querySelectorAll(sel))}

async function api(url, method="GET", body=null){
  const opt = {method, headers:{"Content-Type":"application/json"}}
  if(body!==null) opt.body = JSON.stringify(body)
  const r = await fetch(url, opt)
  const ct = r.headers.get("content-type") || ""
  let data = null
  if(ct.includes("application/json")){
    data = await r.json().catch(()=>null)
  }else{
    data = await r.text().catch(()=>"")
  }
  if(!r.ok){
    const msg = (data && data.detail) ? data.detail : (typeof data === "string" ? data : "请求失败")
    throw new Error(msg)
  }
  return data
}

function setText(el, t){ if(el) el.textContent = t }
function badge(ok){
  if(ok===true) return '<span class="badge good">在线</span>'
  if(ok===false) return '<span class="badge bad">离线</span>'
  return '<span class="badge warn">未知</span>'
}

function escapeHtml(s){
  return (s||"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"','&quot;')
}

function showToast(msg){
  const t = qs('#toast')
  if(!t) return alert(msg)
  t.classList.remove('hidden')
  t.innerHTML = escapeHtml(msg)
  setTimeout(()=>t.classList.add('hidden'), 3000)
}

async function refreshIndex(){
  const list = qs('#agentsList')
  if(!list) return
  const data = await api('/api/agents')
  const agents = data.agents || []
  // For each agent, fetch service in parallel
  await Promise.allSettled(agents.map(async (a)=>{
    try{
      const s = await api(`/api/agents/${a.id}/service`)
      const row = qs(`[data-agent-row="${a.id}"]`)
      if(!row) return
      const state = qs('[data-state]', row)
      state.innerHTML = badge(true)
      setText(qs('[data-realm]', row), s.realm_status || '-')
      setText(qs('[data-rules]', row), `${s.rules_enabled||0}/${s.rules_total||0}`)
      setText(qs('[data-last]', row), new Date((s.now||Date.now()/1000)*1000).toLocaleString())
    }catch(e){
      const row = qs(`[data-agent-row="${a.id}"]`)
      if(!row) return
      const state = qs('[data-state]', row)
      state.innerHTML = badge(false)
      setText(qs('[data-realm]', row), '-')
      setText(qs('[data-rules]', row), '-')
    }
  }))
}

function ruleTypeLabel(t){
  if(t==='tcp_udp') return 'TCP/UDP'
  if(t==='wss_client') return 'WSS 客户端'
  if(t==='wss_server') return 'WSS 服务端'
  return t
}

function renderTargets(targets){
  if(!targets || targets.length===0) return '<span class="muted">(无目标)</span>'
  return targets.map(t=>`<span class="pill">${escapeHtml(t)}</span>`).join(' ')
}

function renderRuleRow(agentId, r, status){
  const enabled = !!r.enabled
  const state = enabled ? '<span class="badge good">运行</span>' : '<span class="badge warn">暂停</span>'
  const type = ruleTypeLabel(r.type)

  // status.connections & target_status is returned in service
  const conn = (status && status.connections && status.connections[r.id]) ? status.connections[r.id] : null
  const inbound = conn && typeof conn.inbound==='number' ? conn.inbound : 0
  let outboundCount = 0
  if(conn && conn.outbound){
    try{
      outboundCount = Object.values(conn.outbound).reduce((a,b)=>a + (typeof b==='number'?b:0), 0)
    }catch(_){ outboundCount = 0 }
  }
  const connTxt = `<span class="mono">入:${inbound} 出:${outboundCount}</span>`

  const tstat = (status && status.target_status && status.target_status[r.id]) ? status.target_status[r.id] : null
  const tstatHtml = tstat ? Object.entries(tstat).map(([t,ok])=>{
    const c = ok ? 'good' : 'bad'
    return `<span class="pill ${c}">${escapeHtml(t)} ${ok?'通':'断'}</span>`
  }).join(' ') : ''

  return `
  <tr>
    <td>
      <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap">
        ${state}
        <span class="mono">#${escapeHtml(r.listen)}</span>
        <span class="pill">${type}</span>
        <span class="muted">${escapeHtml(r.name||'')}</span>
      </div>
      <div style="margin-top:8px; display:flex; flex-wrap:wrap; gap:6px">
        ${renderTargets(r.targets)}
      </div>
      ${tstatHtml ? `<div style="margin-top:8px; display:flex; flex-wrap:wrap; gap:6px">${tstatHtml}</div>` : ''}
    </td>
    <td>${connTxt}</td>
    <td style="white-space:nowrap">
      <button class="btn" data-action="toggle" data-id="${escapeHtml(r.id)}">${enabled?'暂停':'启用'}</button>
      <button class="btn danger" data-action="del" data-id="${escapeHtml(r.id)}">删除</button>
    </td>
  </tr>
  `
}

async function refreshAgentDetail(){
  const root = qs('[data-agent-id]')
  if(!root) return
  const agentId = root.getAttribute('data-agent-id')
  try{
    const service = await api(`/api/agents/${agentId}/service`)
    setText(qs('#realmState'), service.realm_status || '-')
    setText(qs('#rulesCount'), `${service.rules_enabled||0}/${service.rules_total||0}`)
    setText(qs('#nowTs'), new Date((service.now||Date.now()/1000)*1000).toLocaleString())

    const rulesData = await api(`/api/agents/${agentId}/rules`)
    const rules = rulesData.rules || []
    const tbody = qs('#rulesBody')
    if(tbody){
      tbody.innerHTML = rules.map(r=>renderRuleRow(agentId, r, service)).join('')
      qsa('button[data-action]', tbody).forEach(btn=>{
        btn.addEventListener('click', async ()=>{
          const act = btn.getAttribute('data-action')
          const rid = btn.getAttribute('data-id')
          try{
            if(act==='toggle'){
              const toEnable = btn.textContent.trim() === '启用'
              await api(`/api/agents/${agentId}/rules/${rid}/toggle`, 'POST', {enabled: toEnable})
              showToast('已更新规则状态')
              await refreshAgentDetail()
            }else if(act==='del'){
              if(!confirm('确定删除这条规则？')) return
              await api(`/api/agents/${agentId}/rules/${rid}`, 'DELETE')
              showToast('已删除规则')
              await refreshAgentDetail()
            }
          }catch(e){
            showToast(e.message || '操作失败')
          }
        })
      })
    }
  }catch(e){
    showToast(e.message || '刷新失败')
  }
}

function openModal(id){
  const m = qs(id)
  if(!m) return
  m.classList.add('show')
  qs('body').style.overflow='hidden'
}
function closeModal(id){
  const m = qs(id)
  if(!m) return
  m.classList.remove('show')
  qs('body').style.overflow='auto'
}

function syncWssFields(){
  const type = qs('#ruleType')?.value || 'tcp_udp'
  const wss = qs('#wssBox')
  const pair = qs('#pairBox')
  if(wss) wss.classList.toggle('hidden', !(type==='wss_client' || type==='wss_server'))
  if(pair) pair.classList.toggle('hidden', !(type==='wss_client'))
  const cert = qs('#certHint')
  if(cert) cert.classList.toggle('hidden', !(type==='wss_server'))
}

async function bindRuleModal(){
  const root = qs('[data-agent-id]')
  if(!root) return
  const agentId = root.getAttribute('data-agent-id')

  const btnOpen = qs('#btnAddRule')
  if(btnOpen){
    btnOpen.addEventListener('click', ()=>{openModal('#ruleModal'); syncWssFields()})
  }
  qsa('[data-close-modal]').forEach(b=>b.addEventListener('click', ()=>closeModal('#ruleModal')))
  const t = qs('#ruleType')
  if(t) t.addEventListener('change', syncWssFields)

  const form = qs('#ruleForm')
  if(!form) return
  form.addEventListener('submit', async (ev)=>{
    ev.preventDefault()
    try{
      const name = qs('#ruleName').value.trim() || 'Rule'
      const listen_port = parseInt(qs('#listenPort').value, 10)
      const type = qs('#ruleType').value
      const protocol = qs('#proto').value
      const balance = qs('#balance').value
      const enabled = qs('#enabled').checked
      const targetsRaw = qs('#targets').value.trim()
      const targets = targetsRaw ? targetsRaw.split(/\n+/).map(s=>s.trim()).filter(Boolean) : []
      if(!listen_port || listen_port<1 || listen_port>65535) throw new Error('本地端口不正确')
      if(targets.length===0 && type!=='wss_server') throw new Error('请至少填写一个目标地址')

      const payload = {name, listen_port, type, protocol, targets, balance, enabled}

      if(type==='wss_client'){
        const pairCode = qs('#pairCode').value.trim()
        if(pairCode) payload.wss_pair_code = pairCode
        payload.wss_host = qs('#wssHost').value.trim() || null
        payload.wss_path = qs('#wssPath').value.trim() || null
        payload.wss_sni = qs('#wssSni').value.trim() || null
        payload.wss_insecure = qs('#wssInsecure').checked
      }
      if(type==='wss_server'){
        payload.wss_host = qs('#wssHost').value.trim() || null
        payload.wss_path = qs('#wssPath').value.trim() || null
        payload.wss_sni = qs('#wssSni').value.trim() || null
        payload.wss_insecure = qs('#wssInsecure').checked
      }

      const res = await api(`/api/agents/${agentId}/rules`, 'POST', payload)
      closeModal('#ruleModal')
      if(res.pair_code){
        // Show WSS pairing code
        const code = res.pair_code
        const box = qs('#pairOut')
        if(box){
          box.classList.remove('hidden')
          setText(qs('#pairOutCode'), code)
          qs('#btnCopyPair').onclick = async ()=>{
            await navigator.clipboard.writeText(code).catch(()=>{})
            showToast('已复制对接码')
          }
        }
      }
      showToast('规则已创建')
      await refreshAgentDetail()
    }catch(e){
      showToast(e.message || '创建失败')
    }
  })

  const btnApply = qs('#btnApply')
  if(btnApply){
    btnApply.addEventListener('click', async ()=>{
      try{
        await api(`/api/agents/${agentId}/apply`, 'POST', {})
        showToast('已应用配置')
        await refreshAgentDetail()
      }catch(e){
        showToast(e.message || '应用失败')
      }
    })
  }
}

window.addEventListener('DOMContentLoaded', async ()=>{
  try{
    await refreshIndex()
    await refreshAgentDetail()
    await bindRuleModal()
    // periodic
    if(qs('#agentsList')) setInterval(()=>refreshIndex().catch(()=>{}), 4000)
    if(qs('[data-agent-id]')) setInterval(()=>refreshAgentDetail().catch(()=>{}), 2500)
  }catch(e){
    // ignore
  }
})

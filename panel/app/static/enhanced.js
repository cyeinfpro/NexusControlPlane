/**
 * Enhanced Features for Realm Panel
 * - Batch Operations (enable/disable/copy/delete multiple rules)
 * - Rule Metadata (notes, tags, favorites)
 * - Advanced Filtering (by tag, favorite status)
 * - Traffic/Connection History Charts
 */

(function() {
  'use strict';

  // Helper: get element by ID (try multiple ID variants)
  function $(id) {
    return document.getElementById(id);
  }

  // Helper: escape HTML
  function escapeHtml(str) {
    if (str == null) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
  }

  // Helper: format bytes
  function formatBytes(bytes) {
    if (bytes == null || isNaN(bytes)) return '-';
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  // Helper: get current node ID
  function getNodeId() {
    if (window.__NODE_ID__) return window.__NODE_ID__;
    if (window.PAGE && window.PAGE.nodeId) return window.PAGE.nodeId;
    // Try to extract from URL
    const match = window.location.pathname.match(/\/nodes\/(\d+)/);
    return match ? match[1] : null;
  }

  // Helper: get current pool endpoints
  function getEndpoints() {
    if (window.CURRENT_POOL && window.CURRENT_POOL.endpoints) {
      return window.CURRENT_POOL.endpoints;
    }
    return [];
  }

  // =====================
  // Toast Notifications
  // =====================
  const Toast = {
    container: null,

    init() {
      if (!this.container) {
        this.container = document.createElement('div');
        this.container.className = 'toast-container';
        document.body.appendChild(this.container);
      }
    },

    show(message, type = 'info', duration = 3000) {
      this.init();
      const toast = document.createElement('div');
      toast.className = `toast ${type}`;
      toast.textContent = message;
      this.container.appendChild(toast);

      setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 300);
      }, duration);
    },

    success(msg) { this.show(msg, 'success'); },
    error(msg) { this.show(msg, 'error', 5000); },
    warning(msg) { this.show(msg, 'warning'); },
    info(msg) { this.show(msg, 'info'); }
  };

  // =====================
  // Batch Operations
  // =====================
  const BatchOps = {
    selected: new Set(),

    toggle(idx, checked) {
      if (checked) {
        this.selected.add(idx);
      } else {
        this.selected.delete(idx);
      }
      this.updateUI();
    },

    toggleAll(checked) {
      const endpoints = getEndpoints();
      this.selected.clear();
      if (checked) {
        endpoints.forEach((_, idx) => this.selected.add(idx));
      }
      // Update all checkboxes
      document.querySelectorAll('.rule-checkbox').forEach((cb, i) => {
        cb.checked = checked;
      });
      // Update header checkboxes
      const headerCb = $('headerSelectAll') || $('header_select_all') || $('batch_select_all');
      if (headerCb) headerCb.checked = checked;
      const batchSelectAll = $('batchSelectAll') || $('batch_select_all');
      if (batchSelectAll) batchSelectAll.checked = checked;
      this.updateUI();
    },

    clear() {
      this.selected.clear();
      document.querySelectorAll('.rule-checkbox').forEach(cb => cb.checked = false);
      const headerCb = $('headerSelectAll') || $('header_select_all');
      if (headerCb) headerCb.checked = false;
      const batchSelectAll = $('batchSelectAll') || $('batch_select_all');
      if (batchSelectAll) batchSelectAll.checked = false;
      this.updateUI();
    },

    updateUI() {
      const count = this.selected.size;
      const toolbar = $('batchToolbar') || $('batch_toolbar');
      const countEl = $('batchCount') || $('batch_count');

      if (toolbar) {
        toolbar.style.display = count > 0 ? 'block' : 'none';
      }
      if (countEl) {
        countEl.textContent = `已选 ${count} 项`;
      }

      // Highlight selected rows using data-rule-idx attribute
      document.querySelectorAll('#rulesBody tr, #rules_table tbody tr').forEach((tr) => {
        const ruleIdx = parseInt(tr.dataset.ruleIdx, 10);
        if (!isNaN(ruleIdx)) {
          tr.classList.toggle('selected', this.selected.has(ruleIdx));
        }
      });
    },

    async execute(action) {
      if (this.selected.size === 0) {
        Toast.warning('请先选择规则');
        return;
      }

      const nodeId = getNodeId();
      if (!nodeId) {
        Toast.error('无法获取节点ID');
        return;
      }

      const indices = Array.from(this.selected);
      const actionNames = {
        'enable': '启用',
        'disable': '暂停',
        'copy': '复制',
        'delete': '删除'
      };

      if (action === 'delete') {
        if (!confirm(`确定要删除选中的 ${indices.length} 条规则吗？此操作不可撤销。`)) {
          return;
        }
      }

      try {
        const resp = await fetch(`/api/nodes/${nodeId}/rules/batch`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action, indices })
        });
        const data = await resp.json();

        if (data.ok) {
          Toast.success(`成功${actionNames[action]} ${data.modified || indices.length} 条规则`);
          this.clear();
          // Reload pool data from server
          if (typeof loadPool === 'function') {
            await loadPool();
          } else if (typeof window.loadPool === 'function') {
            await window.loadPool();
          } else {
            location.reload();
          }
        } else {
          Toast.error(data.error || '操作失败');
        }
      } catch (err) {
        Toast.error('请求失败: ' + err.message);
      }
    }
  };

  // =====================
  // Rule Metadata
  // =====================
  const RuleMeta = {
    currentIndex: null,

    openEditor(idx) {
      const endpoints = getEndpoints();
      if (idx < 0 || idx >= endpoints.length) {
        Toast.error('规则不存在');
        return;
      }

      const rule = endpoints[idx];
      this.currentIndex = idx;

      // Fill form fields
      const noteEl = $('metaNote') || $('meta_note');
      const tagsEl = $('metaTags') || $('meta_tags');
      const favEl = $('metaFavorite') || $('meta_favorite');
      const idxEl = $('metaRuleIndex') || $('meta_rule_index');

      if (noteEl) noteEl.value = rule.note || '';
      if (tagsEl) tagsEl.value = (rule.tags || []).join(', ');
      if (favEl) favEl.checked = !!rule.favorite;
      if (idxEl) idxEl.value = idx;

      // Update character count
      this.updateNoteCount();

      // Show modal
      const modal = $('metaModal') || $('meta_modal');
      if (modal) modal.style.display = 'flex';
    },

    closeEditor() {
      const modal = $('metaModal') || $('meta_modal');
      if (modal) modal.style.display = 'none';
      this.currentIndex = null;
    },

    updateNoteCount() {
      const noteEl = $('metaNote') || $('meta_note');
      const countEl = $('metaNoteCount') || $('meta_note_count');
      if (noteEl && countEl) {
        countEl.textContent = (noteEl.value || '').length;
      }
    },

    async save() {
      const nodeId = getNodeId();
      if (!nodeId || this.currentIndex === null) {
        Toast.error('无效状态');
        return;
      }

      const noteEl = $('metaNote') || $('meta_note');
      const tagsEl = $('metaTags') || $('meta_tags');
      const favEl = $('metaFavorite') || $('meta_favorite');

      const note = (noteEl?.value || '').trim().slice(0, 500);
      const tagsRaw = (tagsEl?.value || '').trim();
      const tags = tagsRaw ? tagsRaw.split(/[,，]/).map(t => t.trim()).filter(t => t).slice(0, 10) : [];
      const favorite = !!favEl?.checked;

      try {
        const resp = await fetch(`/api/nodes/${nodeId}/rules/${this.currentIndex}/metadata`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ note, tags, favorite })
        });
        const data = await resp.json();

        if (data.ok) {
          Toast.success('元数据已保存');
          // Update local CURRENT_POOL data
          const endpoints = getEndpoints();
          if (endpoints[this.currentIndex]) {
            endpoints[this.currentIndex].note = note;
            endpoints[this.currentIndex].tags = tags;
            endpoints[this.currentIndex].favorite = favorite;
          }
          this.closeEditor();
          // Refresh rules display
          if (typeof renderRules === 'function') {
            renderRules();
          } else if (typeof window.loadNodeData === 'function') {
            window.loadNodeData();
          }
        } else {
          Toast.error(data.error || '保存失败');
        }
      } catch (err) {
        Toast.error('请求失败: ' + err.message);
      }
    },

    async toggleFavorite(idx) {
      const nodeId = getNodeId();
      const endpoints = getEndpoints();
      if (!nodeId || idx < 0 || idx >= endpoints.length) return;

      const rule = endpoints[idx];
      const newFav = !rule.favorite;

      try {
        const resp = await fetch(`/api/nodes/${nodeId}/rules/${idx}/metadata`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ favorite: newFav })
        });
        const data = await resp.json();

        if (data.ok) {
          Toast.success(newFav ? '已收藏' : '已取消收藏');
          // Update local state
          rule.favorite = newFav;
          // Refresh display
          if (typeof renderRules === 'function') {
            renderRules();
          }
        } else {
          Toast.error(data.error || '操作失败');
        }
      } catch (err) {
        Toast.error('请求失败: ' + err.message);
      }
    }
  };

  // =====================
  // Rule Filtering
  // =====================
  const RuleFilter = {
    currentFilter: 'all',
    currentTag: '',
    searchQuery: '',

    init() {
      this.populateTagDropdown();
    },

    populateTagDropdown() {
      const endpoints = getEndpoints();
      const tags = new Set();
      endpoints.forEach(e => {
        if (e.tags && Array.isArray(e.tags)) {
          e.tags.forEach(t => tags.add(t));
        }
      });

      const dropdown = $('tagFilterSelect') || $('tag_filter');
      if (dropdown) {
        // Clear existing options except first
        while (dropdown.options.length > 1) {
          dropdown.remove(1);
        }
        // Add tag options
        Array.from(tags).sort().forEach(tag => {
          const opt = document.createElement('option');
          opt.value = tag;
          opt.textContent = tag;
          dropdown.appendChild(opt);
        });
      }
    },

    matchesRule(rule, idx) {
      // Search query
      if (this.searchQuery) {
        const q = this.searchQuery.toLowerCase();
        const searchable = [
          rule.listen || '',
          rule.remote || '',
          (rule.remotes || []).join(' '),
          rule.note || '',
          (rule.tags || []).join(' ')
        ].join(' ').toLowerCase();
        if (!searchable.includes(q)) return false;
      }

      // Type filter
      switch (this.currentFilter) {
        case 'running':
          if (rule.disabled) return false;
          break;
        case 'disabled':
          if (!rule.disabled) return false;
          break;
        case 'wss':
          if (!rule.listen_transport?.includes('ws') && !rule.remote_transport?.includes('ws')) return false;
          break;
        case 'lb':
          if (!(rule.remotes && rule.remotes.length > 1)) return false;
          break;
        case 'favorite':
          if (!rule.favorite) return false;
          break;
      }

      // Tag filter
      if (this.currentTag) {
        if (!rule.tags || !rule.tags.includes(this.currentTag)) return false;
      }

      return true;
    }
  };

  // =====================
  // Traffic Chart
  // =====================
  const TrafficChart = {
    chart: null,
    currentRuleIdx: null,

    openModal(ruleIdx) {
      this.currentRuleIdx = ruleIdx;
      const modal = $('trafficModal') || $('traffic_modal');
      if (modal) modal.style.display = 'flex';
      this.loadData();
    },

    closeModal() {
      const modal = $('trafficModal') || $('traffic_modal');
      if (modal) modal.style.display = 'none';
      this.currentRuleIdx = null;
    },

    async loadData() {
      const nodeId = getNodeId();
      if (!nodeId) return;

      const rangeEl = $('trafficRange') || $('traffic_range');
      const range = rangeEl ? parseInt(rangeEl.value) : 86400000;
      const since = Date.now() - range;

      // Calculate bucket size (aim for ~100 data points)
      const bucket = Math.max(60000, Math.floor(range / 100));

      let url = `/api/nodes/${nodeId}/traffic/rollup?since=${since}&bucket=${bucket}`;
      if (this.currentRuleIdx !== null) {
        url += `&rule_idx=${this.currentRuleIdx}`;
      }

      try {
        const resp = await fetch(url);
        const data = await resp.json();

        if (data.ok && data.data) {
          this.renderChart(data.data, bucket);
          this.updateTotals(data.data);
        } else {
          Toast.error(data.error || '获取数据失败');
        }
      } catch (err) {
        Toast.error('请求失败: ' + err.message);
      }
    },

    renderChart(data, bucket) {
      const ctx = ($('trafficChart') || $('traffic_chart'))?.getContext('2d');
      if (!ctx) return;

      // Prepare data
      const labels = data.map(d => {
        const date = new Date(d.bucket_ts_ms || d.ts_ms);
        return date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
      });

      const rxData = data.map(d => (d.rx_bytes || 0) / 1024 / 1024); // MB
      const txData = data.map(d => (d.tx_bytes || 0) / 1024 / 1024); // MB
      const connData = data.map(d => d.connections || 0);

      // Destroy existing chart
      if (this.chart) {
        this.chart.destroy();
      }

      // Create new chart
      this.chart = new Chart(ctx, {
        type: 'line',
        data: {
          labels,
          datasets: [
            {
              label: '接收 (MB)',
              data: rxData,
              borderColor: 'rgba(34, 197, 94, 0.8)',
              backgroundColor: 'rgba(34, 197, 94, 0.1)',
              fill: true,
              yAxisID: 'y'
            },
            {
              label: '发送 (MB)',
              data: txData,
              borderColor: 'rgba(59, 130, 246, 0.8)',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              fill: true,
              yAxisID: 'y'
            },
            {
              label: '连接数',
              data: connData,
              borderColor: 'rgba(245, 158, 11, 0.8)',
              backgroundColor: 'transparent',
              borderDash: [5, 5],
              yAxisID: 'y1'
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            mode: 'index',
            intersect: false
          },
          scales: {
            y: {
              type: 'linear',
              position: 'left',
              title: { display: true, text: '流量 (MB)' }
            },
            y1: {
              type: 'linear',
              position: 'right',
              title: { display: true, text: '连接数' },
              grid: { drawOnChartArea: false }
            }
          },
          plugins: {
            legend: { position: 'top' }
          }
        }
      });
    },

    updateTotals(data) {
      let rxTotal = 0, txTotal = 0;
      data.forEach(d => {
        rxTotal += d.rx_bytes || 0;
        txTotal += d.tx_bytes || 0;
      });

      const rxEl = $('trafficRxTotal') || $('traffic_rx_total');
      const txEl = $('trafficTxTotal') || $('traffic_tx_total');
      if (rxEl) rxEl.textContent = formatBytes(rxTotal);
      if (txEl) txEl.textContent = formatBytes(txTotal);
    }
  };

  // =====================
  // Global Filter Functions
  // =====================
  
  // Store original setRuleFilter if it exists
  const originalSetRuleFilter = window.setRuleFilter;
  
  window.setRuleFilter = function(query) {
    // Update both our RuleFilter and the original RULE_FILTER
    RuleFilter.searchQuery = query;
    if (typeof window.RULE_FILTER !== 'undefined' || originalSetRuleFilter) {
      // Call original function which updates RULE_FILTER and calls renderRules
      if (originalSetRuleFilter) {
        originalSetRuleFilter(query);
      } else {
        window.RULE_FILTER = query;
        if (typeof renderRules === 'function') renderRules();
      }
    } else {
      if (typeof renderRules === 'function') renderRules();
    }
  };

  window.applyRuleTypeFilter = function(filter) {
    RuleFilter.currentFilter = filter;
    if (typeof renderRules === 'function') renderRules();
  };

  window.applyTagFilter = function(tag) {
    RuleFilter.currentTag = tag;
    if (typeof renderRules === 'function') renderRules();
  };

  // =====================
  // Expose to global scope
  // =====================
  window.BatchOps = BatchOps;
  window.RuleMeta = RuleMeta;
  window.RuleFilter = RuleFilter;
  window.TrafficChart = TrafficChart;
  window.Toast = Toast;

  // Initialize on DOM ready
  document.addEventListener('DOMContentLoaded', function() {
    // Setup note character counter
    const noteEl = $('metaNote') || $('meta_note');
    if (noteEl) {
      noteEl.addEventListener('input', () => RuleMeta.updateNoteCount());
    }

    // Populate tag dropdown after pool loads
    const checkPool = setInterval(() => {
      if (window.CURRENT_POOL) {
        RuleFilter.populateTagDropdown();
        clearInterval(checkPool);
      }
    }, 500);

    // Clear interval after 10 seconds
    setTimeout(() => clearInterval(checkPool), 10000);
  });

  // =====================
  // Extend renderRules if exists
  // =====================
  const originalRenderRules = window.renderRules;
  if (typeof originalRenderRules === 'function') {
    window.renderRules = function() {
      // Apply filters before rendering
      const eps = getEndpoints();
      const filtered = [];
      eps.forEach((e, idx) => {
        if (RuleFilter.matchesRule(e, idx)) {
          filtered.push({ e, idx });
        }
      });

      // Store filtered results for the original function
      window.__FILTERED_RULES__ = filtered;

      // Call original
      originalRenderRules.apply(this, arguments);

      // Update batch ops UI after render
      BatchOps.updateUI();

      // Update tag dropdown
      RuleFilter.populateTagDropdown();
    };
  }

})();

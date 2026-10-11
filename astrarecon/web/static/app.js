/**
 * AstraRecon Visual Canvas & Real-time Web Controller
 * Zero-dependency, lightweight client-side application.
 */

// Global State
const state = {
  activeTab: 'canvas',
  isScanning: false,
  activeSessionId: null,
  activeTarget: null,
  activeWorkflow: 'default',
  elapsedTimer: null,
  elapsedSeconds: 0,
  
  // Canvas State
  scale: 1,
  panX: 60,
  panY: 80,
  isDragging: false,
  dragStartX: 0,
  dragStartY: 0,
  selectedNodeId: null,
  
  // Graph Data
  nodes: [],
  edges: [],
  nodeStatuses: {}, // node_id -> { status, item_count, message, elapsed }
  
  // Sessions & Findings
  sessions: [],
  currentResults: { subdomains: [], live_hosts: [], findings: [] },
  tools: {},
};

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initCanvasControls();
  initMissionBar();
  initSSE();
  loadInitialData();
});

/* ==========================================================================
   Navigation & Tabs
   ========================================================================== */

function initNavigation() {
  const tabs = document.querySelectorAll('.nav-tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetTab = tab.dataset.tab;
      switchTab(targetTab);
    });
  });
}

function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll('.nav-tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  document.querySelectorAll('.view-pane').forEach(pane => {
    pane.classList.toggle('active', pane.id === `view-${tabId}`);
  });

  if (tabId === 'sessions') {
    loadSessions();
  } else if (tabId === 'doctor') {
    loadDoctorData();
  } else if (tabId === 'canvas') {
    renderCanvas();
  }
}

/* ==========================================================================
   Server-Sent Events (SSE) & Live Sync
   ========================================================================== */

function initSSE() {
  const evtSource = new EventSource('/api/events');

  evtSource.addEventListener('init', (e) => {
    const data = JSON.parse(e.data);
    updateScanStatus(data);
  });

  evtSource.addEventListener('scan_init', (e) => {
    const data = JSON.parse(e.data);
    state.isScanning = true;
    state.activeSessionId = data.session_id;
    state.activeTarget = data.target;
    state.nodes = data.nodes || [];
    state.edges = data.edges || [];
    state.nodeStatuses = {};
    renderCanvas();
    startElapsedTimer();
    updateLauncherUI(true);
    addLogEntry(`Mission initialized for target: ${data.target}`, 'info');
  });

  evtSource.addEventListener('node_update', (e) => {
    const data = JSON.parse(e.data);
    state.nodeStatuses[data.node_id] = {
      status: data.status,
      item_count: data.item_count,
      message: data.message,
    };
    updateNodeInCanvas(data.node_id, data.status, data.item_count, data.message);
  });

  evtSource.addEventListener('log', (e) => {
    const data = JSON.parse(e.data);
    addLogEntry(data.message, data.level, data.timestamp);
  });

  evtSource.addEventListener('scan_complete', (e) => {
    const data = JSON.parse(e.data);
    state.isScanning = false;
    stopElapsedTimer();
    updateLauncherUI(false);
    addLogEntry(`Mission completed! Discovered ${data.subdomain_count} subdomains, ${data.live_host_count} hosts, ${data.finding_count} vulns.`, 'success');
    if (state.activeSessionId) {
      loadSessionResults(state.activeSessionId);
    }
  });

  evtSource.addEventListener('scan_cancelled', (e) => {
    state.isScanning = false;
    stopElapsedTimer();
    updateLauncherUI(false);
    addLogEntry('Mission aborted by user.', 'warning');
  });

  evtSource.addEventListener('scan_error', (e) => {
    const data = JSON.parse(e.data);
    state.isScanning = false;
    stopElapsedTimer();
    updateLauncherUI(false);
    addLogEntry(`Mission error: ${data.error}`, 'error');
  });

  evtSource.onerror = () => {
    // Reconnects automatically
  };
}

function updateScanStatus(statusData) {
  state.isScanning = statusData.is_scanning;
  state.activeSessionId = statusData.active_session_id;
  state.activeTarget = statusData.active_target;
  state.nodeStatuses = statusData.node_statuses || {};

  if (statusData.is_scanning) {
    state.elapsedSeconds = statusData.elapsed_seconds || 0;
    startElapsedTimer();
    updateLauncherUI(true);
    if (statusData.active_session_id) {
      loadSessionGraph(statusData.active_session_id);
    }
  } else {
    updateLauncherUI(false);
  }
}

/* ==========================================================================
   Mission Controls
   ========================================================================== */

function initMissionBar() {
  const form = document.getElementById('form-mission-launch');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      launchScan();
    });
  }

  const stopBtn = document.getElementById('btn-mission-stop');
  if (stopBtn) {
    stopBtn.addEventListener('click', stopScan);
  }
}

async function launchScan() {
  const targetInput = document.getElementById('input-target');
  const workflowSelect = document.getElementById('select-workflow');
  const profileSelect = document.getElementById('select-profile');

  const target = targetInput.value.trim();
  if (!target) return;

  const payload = {
    target: target,
    workflow: workflowSelect ? workflowSelect.value : 'default',
    profile: profileSelect ? profileSelect.value : 'auto',
  };

  try {
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.error) {
      alert(data.error);
    } else {
      switchTab('canvas');
    }
  } catch (err) {
    alert('Failed to launch scan: ' + err.message);
  }
}

async function stopScan() {
  try {
    await fetch('/api/scan/stop', { method: 'POST' });
  } catch (err) {
    console.error(err);
  }
}

function updateLauncherUI(isScanning) {
  const launchBtn = document.getElementById('btn-mission-launch');
  const stopBtn = document.getElementById('btn-mission-stop');
  const telemetryPill = document.getElementById('telemetry-status-pill');
  const telemetryText = document.getElementById('telemetry-status-text');

  if (launchBtn) launchBtn.disabled = isScanning;
  if (stopBtn) stopBtn.style.display = isScanning ? 'inline-flex' : 'none';

  if (telemetryPill) {
    telemetryPill.classList.toggle('active', isScanning);
  }
  if (telemetryText) {
    if (isScanning) {
      telemetryText.textContent = `RECON: ${state.activeTarget || 'ACTIVE'} [${formatTime(state.elapsedSeconds)}]`;
    } else {
      telemetryText.textContent = 'STANDBY • READY';
    }
  }
}

function startElapsedTimer() {
  stopElapsedTimer();
  state.elapsedTimer = setInterval(() => {
    state.elapsedSeconds += 1;
    const telemetryText = document.getElementById('telemetry-status-text');
    if (telemetryText && state.isScanning) {
      telemetryText.textContent = `RECON: ${state.activeTarget || 'ACTIVE'} [${formatTime(state.elapsedSeconds)}]`;
    }
  }, 1000);
}

function stopElapsedTimer() {
  if (state.elapsedTimer) {
    clearInterval(state.elapsedTimer);
    state.elapsedTimer = null;
  }
}

function formatTime(secs) {
  const m = Math.floor(secs / 60);
  const s = Math.floor(secs % 60);
  return `${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
}

/* ==========================================================================
   Visual DAG Canvas (Hierarchical Topological Layout)
   ========================================================================== */

function initCanvasControls() {
  const container = document.getElementById('canvas-container');
  if (!container) return;

  container.addEventListener('mousedown', (e) => {
    if (e.target.closest('.dag-node') || e.target.closest('.canvas-controls')) return;
    state.isDragging = true;
    state.dragStartX = e.clientX - state.panX;
    state.dragStartY = e.clientY - state.panY;
  });

  window.addEventListener('mousemove', (e) => {
    if (!state.isDragging) return;
    state.panX = e.clientX - state.dragStartX;
    state.panY = e.clientY - state.dragStartY;
    applyCanvasTransform();
  });

  window.addEventListener('mouseup', () => {
    state.isDragging = false;
  });

  container.addEventListener('wheel', (e) => {
    e.preventDefault();
    const zoomFactor = e.deltaY > 0 ? 0.9 : 1.1;
    state.scale = Math.max(0.3, Math.min(2.5, state.scale * zoomFactor));
    applyCanvasTransform();
  }, { passive: false });

  document.getElementById('btn-zoom-in')?.addEventListener('click', () => {
    state.scale = Math.min(2.5, state.scale * 1.2);
    applyCanvasTransform();
  });
  document.getElementById('btn-zoom-out')?.addEventListener('click', () => {
    state.scale = Math.max(0.3, state.scale * 0.8);
    applyCanvasTransform();
  });
  document.getElementById('btn-zoom-reset')?.addEventListener('click', () => {
    state.scale = 1;
    state.panX = 60;
    state.panY = 80;
    applyCanvasTransform();
  });

  // Drawer Close
  document.getElementById('btn-drawer-close')?.addEventListener('click', () => {
    closeNodeDrawer();
  });
}

function applyCanvasTransform() {
  const wrapper = document.getElementById('canvas-viewport');
  if (wrapper) {
    wrapper.style.transform = `translate(${state.panX}px, ${state.panY}px) scale(${state.scale})`;
  }
}

/**
 * Computes topological rank (tiers) for clean left-to-right DAG layout.
 */
function layoutGraph(nodes, edges) {
  const inDegree = {};
  const adj = {};
  nodes.forEach(n => {
    inDegree[n.id] = 0;
    adj[n.id] = [];
  });
  edges.forEach(e => {
    if (adj[e.source]) adj[e.source].push(e.target);
    if (inDegree[e.target] !== undefined) inDegree[e.target]++;
  });

  // Assign tiers
  const tiers = {};
  let queue = nodes.filter(n => inDegree[n.id] === 0).map(n => n.id);
  queue.forEach(id => { tiers[id] = 0; });

  let currentTier = 0;
  while (queue.length > 0) {
    const nextQueue = [];
    queue.forEach(u => {
      (adj[u] || []).forEach(v => {
        tiers[v] = Math.max(tiers[v] || 0, (tiers[u] || 0) + 1);
        inDegree[v]--;
        if (inDegree[v] === 0) {
          nextQueue.push(v);
        }
      });
    });
    queue = nextQueue;
    currentTier++;
  }

  // Position nodes
  const tierGroups = {};
  nodes.forEach(n => {
    const t = tiers[n.id] || 0;
    if (!tierGroups[t]) tierGroups[t] = [];
    tierGroups[t].push(n);
  });

  const nodePositions = {};
  const colSpacing = 320;
  const rowSpacing = 130;

  Object.keys(tierGroups).forEach(t => {
    const colNodes = tierGroups[t];
    const colX = parseInt(t) * colSpacing;
    const startY = Math.max(0, (5 - colNodes.length) * 40);

    colNodes.forEach((node, idx) => {
      nodePositions[node.id] = {
        x: colX,
        y: startY + idx * rowSpacing,
      };
    });
  });

  return nodePositions;
}

function renderCanvas() {
  const nodeLayer = document.getElementById('canvas-node-layer');
  const svgLayer = document.getElementById('canvas-svg-layer');
  if (!nodeLayer || !svgLayer) return;

  nodeLayer.innerHTML = '';
  svgLayer.innerHTML = '';

  if (!state.nodes || state.nodes.length === 0) {
    renderDefaultPlaceholderGraph();
    return;
  }

  const positions = layoutGraph(state.nodes, state.edges);

  // 1. Render Edges (Curved Bezier Paths)
  state.edges.forEach(edge => {
    const p1 = positions[edge.source];
    const p2 = positions[edge.target];
    if (!p1 || !p2) return;

    const x1 = p1.x + 220; // right of node card
    const y1 = p1.y + 36;  // middle height
    const x2 = p2.x;       // left of target node
    const y2 = p2.y + 36;

    const dx = Math.abs(x2 - x1) * 0.5;
    const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    path.setAttribute('id', `edge-${edge.source}-${edge.target}`);
    path.setAttribute('class', 'canvas-edge');
    svgLayer.appendChild(path);
  });

  // 2. Render Nodes
  state.nodes.forEach(node => {
    const pos = positions[node.id] || { x: 0, y: 0 };
    const st = state.nodeStatuses[node.id] || { status: 'WAITING' };

    const card = document.createElement('div');
    card.id = `node-${node.id}`;
    card.className = `dag-node state-${st.status.toLowerCase()}`;
    card.style.left = `${pos.x}px`;
    card.style.top = `${pos.y}px`;

    const icon = getNodeIcon(node.type);
    const label = node.label || node.id.replace('_', ' ').toUpperCase();

    card.innerHTML = `
      <div class="dag-node-header">
        <span class="dag-node-title">${icon} ${label}</span>
        <span class="dag-node-stage">${getNodeStage(node.type)}</span>
      </div>
      <div class="dag-node-body">
        <span class="dag-node-status" id="status-text-${node.id}">
          ${getStatusBadge(st.status)}
        </span>
        <span class="dag-node-counter" id="counter-${node.id}">
          ${st.item_count ? `+${st.item_count}` : ''}
        </span>
      </div>
    `;

    card.addEventListener('click', () => {
      openNodeDrawer(node);
    });

    nodeLayer.appendChild(card);
  });

  applyCanvasTransform();
}

function renderDefaultPlaceholderGraph() {
  // Renders standard default DAG preview if no scan is loaded yet
  const defaultNodes = [
    { id: 'target_input', type: 'builtin.target_input', label: 'Target Input' },
    { id: 'scope_guard', type: 'builtin.scope_guard', label: 'Scope Guard' },
    { id: 'subfinder', type: 'plugin.subfinder', label: 'Subfinder' },
    { id: 'assetfinder', type: 'plugin.assetfinder', label: 'Assetfinder' },
    { id: 'union_dedupe', type: 'builtin.union_dedupe', label: 'Union Dedupe' },
    { id: 'dnsx', type: 'plugin.dnsx', label: 'DNSX Validation' },
    { id: 'httpx', type: 'plugin.httpx', label: 'HTTPX Probing' },
    { id: 'nuclei', type: 'plugin.nuclei', label: 'Nuclei Vuln Audit' },
  ];
  const defaultEdges = [
    { source: 'target_input', target: 'scope_guard' },
    { source: 'scope_guard', target: 'subfinder' },
    { source: 'scope_guard', target: 'assetfinder' },
    { source: 'subfinder', target: 'union_dedupe' },
    { source: 'assetfinder', target: 'union_dedupe' },
    { source: 'union_dedupe', target: 'dnsx' },
    { source: 'dnsx', target: 'httpx' },
    { source: 'httpx', target: 'nuclei' },
  ];
  state.nodes = defaultNodes;
  state.edges = defaultEdges;
  renderCanvas();
}

function updateNodeInCanvas(nodeId, status, itemCount, message) {
  const card = document.getElementById(`node-${nodeId}`);
  if (!card) return;

  card.className = `dag-node state-${status.toLowerCase()}`;
  const statusEl = document.getElementById(`status-text-${nodeId}`);
  if (statusEl) {
    statusEl.innerHTML = getStatusBadge(status);
  }
  const counterEl = document.getElementById(`counter-${nodeId}`);
  if (counterEl && itemCount) {
    counterEl.textContent = `+${itemCount}`;
  }

  // Update connected edges
  state.edges.forEach(edge => {
    if (edge.source === nodeId) {
      const edgeEl = document.getElementById(`edge-${edge.source}-${edge.target}`);
      if (edgeEl) {
        if (status === 'RUNNING') edgeEl.classList.add('active');
        if (status === 'SUCCESS' || status === 'COMPLETED') {
          edgeEl.classList.remove('active');
          edgeEl.classList.add('completed');
        }
      }
    }
  });
}

function getStatusBadge(status) {
  const norm = (status || 'WAITING').toUpperCase();
  switch (norm) {
    case 'RUNNING':
      return '<span style="color:var(--color-primary);">▶ Running</span>';
    case 'SUCCESS':
    case 'COMPLETED':
      return '<span style="color:var(--color-success);">✔ Done</span>';
    case 'CACHED':
      return '<span style="color:var(--color-purple);">◈ Cached</span>';
    case 'FAILED':
      return '<span style="color:var(--color-error);">✖ Failed</span>';
    case 'SKIPPED':
      return '<span style="color:var(--color-muted);">○ Skipped</span>';
    default:
      return '<span style="color:var(--color-dim);">● Waiting</span>';
  }
}

function getNodeIcon(type) {
  if (type.includes('target')) return '🎯';
  if (type.includes('scope')) return '🛡️';
  if (type.includes('dedupe')) return '⚡';
  if (type.includes('subfinder') || type.includes('subenum') || type.includes('amass') || type.includes('assetfinder')) return '🔍';
  if (type.includes('dns')) return '🌐';
  if (type.includes('http')) return '🚀';
  if (type.includes('port') || type.includes('naabu')) return '🔌';
  if (type.includes('crawl') || type.includes('katana') || type.includes('gau') || type.includes('wayback')) return '🕷️';
  if (type.includes('nuclei') || type.includes('dalfox') || type.includes('vuln')) return '💥';
  return '⚙️';
}

function getNodeStage(type) {
  if (type.startsWith('builtin.')) return 'Core';
  return 'Arsenal';
}

/* ==========================================================================
   Node Inspector Drawer
   ========================================================================== */

async function openNodeDrawer(node) {
  state.selectedNodeId = node.id;
  const drawer = document.getElementById('node-drawer');
  if (!drawer) return;

  document.getElementById('drawer-node-name').textContent = node.label || node.id;
  document.getElementById('drawer-node-type').textContent = node.type;

  const st = state.nodeStatuses[node.id] || { status: 'WAITING' };
  document.getElementById('drawer-node-status').innerHTML = getStatusBadge(st.status);

  // Fetch node logs if available
  const logBox = document.getElementById('drawer-log-content');
  if (logBox) {
    logBox.textContent = 'Streaming logs from disk...';
    if (state.activeSessionId) {
      try {
        const res = await fetch(`/api/session/${state.activeSessionId}/logs/${node.id}`);
        const data = await res.json();
        const output = (data.stdout + '\n' + data.stderr).trim();
        logBox.textContent = output || '(No output recorded yet for this stage)';
      } catch (err) {
        logBox.textContent = '(Logs unavailable)';
      }
    } else {
      logBox.textContent = '(Logs will appear when scan executes)';
    }
  }

  drawer.classList.add('open');
}

function closeNodeDrawer() {
  state.selectedNodeId = null;
  const drawer = document.getElementById('node-drawer');
  if (drawer) drawer.classList.remove('open');
}

/* ==========================================================================
   Terminal Console Log Streaming
   ========================================================================== */

function addLogEntry(message, level = 'info', timestamp = null) {
  const consolePane = document.getElementById('console-log-stream');
  if (!consolePane) return;

  const timeStr = timestamp ? new Date(timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `
    <span class="log-time">${timeStr}</span>
    <span class="log-level ${level}">${level}</span>
    <span class="log-text">${escapeHtml(message)}</span>
  `;
  consolePane.appendChild(entry);
  consolePane.scrollTop = consolePane.scrollHeight;
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* ==========================================================================
   Findings & Data Tabs
   ========================================================================== */

async function loadSessionResults(sessionId) {
  try {
    const res = await fetch(`/api/session/${sessionId}/results`);
    const data = await res.json();
    state.currentResults = data;
    renderFindings(data);
  } catch (err) {
    console.error('Failed to load session results:', err);
  }
}

function renderFindings(results) {
  // Update stat counters
  document.getElementById('stat-subdomains-count').textContent = results.total_subdomains || 0;
  document.getElementById('stat-hosts-count').textContent = results.total_live_hosts || 0;
  document.getElementById('stat-vulns-count').textContent = results.total_findings || 0;

  // Render Subdomains Table
  const subTbody = document.getElementById('tbody-subdomains');
  if (subTbody) {
    subTbody.innerHTML = '';
    (results.subdomains || []).slice(0, 200).forEach(sub => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:var(--font-mono); font-weight:600; color:var(--color-primary);">${escapeHtml(sub)}</td>
        <td><span class="badge-version">Discovered</span></td>
        <td>
          <button class="btn-secondary" onclick="navigator.clipboard.writeText('${sub}')">Copy</button>
        </td>
      `;
      subTbody.appendChild(tr);
    });
  }

  // Render Live Hosts Table
  const hostTbody = document.getElementById('tbody-hosts');
  if (hostTbody) {
    hostTbody.innerHTML = '';
    (results.live_hosts || []).slice(0, 200).forEach(h => {
      const url = h.url || h.host || '';
      const code = h.status_code || h.status || '200';
      const title = h.title || '--';
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:var(--font-mono);"><a href="${url}" target="_blank" style="color:var(--color-text); text-decoration:none;">${escapeHtml(url)}</a></td>
        <td><span class="badge-version" style="color:var(--color-success); border-color:var(--color-success);">${code}</span></td>
        <td style="color:var(--color-muted);">${escapeHtml(title)}</td>
      `;
      hostTbody.appendChild(tr);
    });
  }

  // Render Vulnerabilities Table
  const vulnTbody = document.getElementById('tbody-vulns');
  if (vulnTbody) {
    vulnTbody.innerHTML = '';
    (results.findings || []).slice(0, 200).forEach(f => {
      const info = f.info || {};
      const name = info.name || f['template-id'] || 'Finding';
      const severity = (info.severity || 'info').toLowerCase();
      const host = f.host || f['matched-at'] || '--';

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><span class="severity-pill severity-${severity}">${severity}</span></td>
        <td style="font-weight:600; color:#fff;">${escapeHtml(name)}</td>
        <td style="font-family:var(--font-mono);">${escapeHtml(host)}</td>
      `;
      vulnTbody.appendChild(tr);
    });
  }
}

/* ==========================================================================
   Sessions Explorer
   ========================================================================== */

async function loadSessions() {
  const tbody = document.getElementById('tbody-sessions');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--color-muted);">Scanning mission archives...</td></tr>';

  try {
    const res = await fetch('/api/sessions');
    const sessions = await res.json();
    state.sessions = sessions;

    tbody.innerHTML = '';
    if (sessions.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; padding:20px; color:var(--color-muted);">No scan sessions recorded yet. Launch a mission above.</td></tr>';
      return;
    }

    sessions.forEach(s => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:var(--font-mono); font-weight:700; color:var(--color-primary);">${s.id}</td>
        <td style="font-weight:600;">${escapeHtml(s.target)}</td>
        <td>${getStatusBadge(s.status)}</td>
        <td style="font-family:var(--font-mono);">${s.subdomains} subs • ${s.live_hosts} hosts • ${s.findings} vulns</td>
        <td style="color:var(--color-muted); font-size:12px;">${new Date(s.started_at).toLocaleString()}</td>
        <td>
          <button class="btn-secondary" onclick="inspectSession('${s.id}')">Inspect</button>
          <a class="btn-secondary" href="/api/session/${s.id}/export/ai" target="_blank" style="text-decoration:none;">AI Bundle</a>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:var(--color-error); padding:20px;">Failed to load sessions: ${err.message}</td></tr>`;
  }
}

async function inspectSession(sessionId) {
  state.activeSessionId = sessionId;
  await loadSessionGraph(sessionId);
  await loadSessionResults(sessionId);
  switchTab('canvas');
}

async function loadSessionGraph(sessionId) {
  try {
    const res = await fetch(`/api/session/${sessionId}`);
    const data = await res.json();
    if (data.workflow && data.workflow.nodes) {
      state.nodes = data.workflow.nodes.map(n => ({
        id: n.id,
        type: n.type,
        label: n.id.replace('_', ' ').toUpperCase(),
      }));
      state.edges = data.workflow.edges || [];
      state.nodeStatuses = {};
      Object.keys(data.checkpoints || {}).forEach(k => {
        const cp = data.checkpoints[k];
        state.nodeStatuses[k] = {
          status: cp.status,
          item_count: Object.values(cp.outputs || {}).reduce((acc, curr) => acc + (curr.lines || 0), 0),
        };
      });
      renderCanvas();
    }
  } catch (err) {
    console.error('Failed to load session graph:', err);
  }
}

/* ==========================================================================
   Doctor / System Grid
   ========================================================================== */

async function loadDoctorData() {
  const grid = document.getElementById('tools-grid');
  if (!grid) return;

  grid.innerHTML = '<div style="color:var(--color-muted);">Inspecting system environment...</div>';

  try {
    const res = await fetch('/api/doctor');
    const data = await res.json();

    document.getElementById('sys-os').textContent = `${data.os_name} ${data.os_version} (${data.arch})`;
    document.getElementById('sys-python').textContent = `Python ${data.python_version}`;
    document.getElementById('sys-go').textContent = data.go_installed ? `Go ${data.go_version || 'installed'}` : 'Missing';
    document.getElementById('sys-tools-count').textContent = `${data.installed_count} / ${data.total_tools} Arsenal Tools Installed`;

    grid.innerHTML = '';
    Object.keys(data.tools || {}).forEach(toolName => {
      const t = data.tools[toolName];
      const card = document.createElement('div');
      card.className = 'tool-card';
      card.innerHTML = `
        <div class="tool-info">
          <span class="tool-name">${toolName}</span>
          <span class="tool-version">${t.installed ? (t.version || 'installed') : 'Not found in PATH'}</span>
        </div>
        <span class="tool-badge ${t.installed ? 'installed' : 'missing'}">
          ${t.installed ? 'INSTALLED' : 'MISSING'}
        </span>
      `;
      grid.appendChild(card);
    });
  } catch (err) {
    grid.innerHTML = `<div style="color:var(--color-error);">Failed to load environment status: ${err.message}</div>`;
  }
}

/* ==========================================================================
   Initial Bootstrapping
   ========================================================================== */

async function loadInitialData() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    updateScanStatus(data);
    if (!data.is_scanning) {
      renderDefaultPlaceholderGraph();
    }
  } catch (err) {
    renderDefaultPlaceholderGraph();
  }
}

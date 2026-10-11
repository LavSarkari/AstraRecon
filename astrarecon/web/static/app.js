/**
 * AstraRecon Visual Canvas & Real-time Web Controller
 * Craftsman UI Controller: Mission Launchpad Cockpit, Scoped Plugin Toggles & Workspaces
 */

// Global Reactive State
const state = {
  activeTab: 'canvas',
  isScanning: false,
  activeSessionId: null,
  activeTarget: null,
  activeWorkflow: 'default',
  elapsedTimer: null,
  elapsedSeconds: 0,
  
  // Canvas Viewport & Pan/Zoom
  scale: 1,
  panX: 80,
  panY: 80,
  isDragging: false,
  dragStartX: 0,
  dragStartY: 0,
  selectedNodeId: null,
  
  // Graph Topology & Runtime States
  nodes: [],
  edges: [],
  nodeStatuses: {}, // node_id -> { status, item_count, message, elapsed }
  
  // Workspaces & Scoped Plugin Hub (Features A, B, C)
  activeWorkspace: { id: 'default', name: 'Global Scope', target: '' },
  projects: [],
  recentEngagements: [],
  disabledTools: new Set(),
  pluginScope: 'global',
  
  // Surface Findings & Session History
  sessions: [],
  currentResults: { subdomains: [], live_hosts: [], findings: [] },
  tools: {},
  systemInfo: {},
  autoScrollTerminal: true,
};
window.state = state;

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  initThemeToggle();
  initNavigation();
  initCanvasControls();
  initMissionBar();
  initHeaderMissionSelector();
  initKeyboardShortcuts();
  initModals();
  initTerminalActions();
  initSSE();
  loadInitialData();
});

/* ==========================================================================
   Navigation & Tab Routing
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
    const isActive = btn.dataset.tab === tabId;
    btn.classList.toggle('active', isActive);
    btn.setAttribute('aria-selected', isActive ? 'true' : 'false');
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
  } else if (tabId === 'findings') {
    loadFindingsTab();
  }
}

/* ==========================================================================
   Theme Controller: Dual-Palette Dark / Light Mode with Persistence
   ========================================================================== */

function getPreferredTheme() {
  const saved = localStorage.getItem('astrarecon_theme');
  if (saved === 'light' || saved === 'dark') return saved;
  return (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark';
}

function applyTheme(theme, showNotification = false) {
  state.theme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('astrarecon_theme', theme);

  const toggleBtn = document.getElementById('btn-theme-toggle');
  const icon = document.getElementById('theme-toggle-icon');
  if (toggleBtn && icon) {
    if (theme === 'light') {
      icon.innerHTML = '<use href="#icon-moon"/>';
      toggleBtn.setAttribute('title', 'Switch to Dark Mode (T)');
      toggleBtn.setAttribute('aria-label', 'Switch to Dark Mode');
    } else {
      icon.innerHTML = '<use href="#icon-sun"/>';
      toggleBtn.setAttribute('title', 'Switch to Light Mode (T)');
      toggleBtn.setAttribute('aria-label', 'Switch to Light Mode');
    }
  }

  // Redraw canvas if DAG is active to sync connectors & node highlights
  if (state.activeTab === 'canvas' && state.nodes && state.nodes.length > 0) {
    renderCanvas();
  }

  if (showNotification) {
    showToast(`Switched to ${theme === 'light' ? 'Tactical Light' : 'Cosmic Obsidian'} theme`, 'info');
  }
}

function toggleTheme() {
  const current = state.theme || getPreferredTheme();
  const next = current === 'dark' ? 'light' : 'dark';
  applyTheme(next, true);
}

function initThemeToggle() {
  const initialTheme = getPreferredTheme();
  applyTheme(initialTheme, false);

  const btn = document.getElementById('btn-theme-toggle');
  if (btn && !btn.dataset.bound) {
    btn.dataset.bound = 'true';
    btn.addEventListener('click', () => {
      toggleTheme();
    });
  }

  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      if (!localStorage.getItem('astrarecon_theme')) {
        applyTheme(e.matches ? 'dark' : 'light', false);
      }
    });
  }
}

/* ==========================================================================
   Server-Sent Events (SSE) & Real-time Telemetry
   ========================================================================== */

function initSSE() {
  const evtSource = new EventSource('/api/events');

  evtSource.addEventListener('init', (e) => {
    const data = JSON.parse(e.data);
    updateScanStatus(data);
  });

  evtSource.addEventListener('log_history', (e) => {
    try {
      const logs = JSON.parse(e.data);
      if (Array.isArray(logs)) {
        logs.forEach(item => {
          addLogEntry(item.message, item.level, item.timestamp);
        });
      }
    } catch (err) {
      console.error('Failed to parse log history:', err);
    }
  });

  evtSource.addEventListener('scan_init', (e) => {
    const data = JSON.parse(e.data);
    state.isScanning = true;
    state.activeSessionId = data.session_id;
    state.activeTarget = data.target;
    state.nodes = data.nodes || [];
    state.edges = normalizeEdges(data.edges || []);
    state.nodeStatuses = {};
    renderCanvas();
    startElapsedTimer();
    updateLauncherUI(true);
    updateHUD();
    addLogEntry(`Mission initialized for target: ${data.target}`, 'info');
    showToast(`Mission started on ${data.target}`, 'success');
  });

  evtSource.addEventListener('node_update', (e) => {
    const data = JSON.parse(e.data);
    state.nodeStatuses[data.node_id] = {
      status: data.status,
      item_count: data.item_count,
      message: data.message,
    };
    updateNodeInCanvas(data.node_id, data.status, data.item_count, data.message);
    if (state.selectedNodeId === data.node_id) {
      updateDrawerContent(data.node_id);
    }
    updateHUD();
  });

  evtSource.addEventListener('log', (e) => {
    const data = JSON.parse(e.data);
    addLogEntry(data.message, data.level, data.timestamp);
    if (state.selectedNodeId && (data.node_id === state.selectedNodeId || !data.node_id)) {
      appendDrawerLog(data.message);
    }
  });

  evtSource.addEventListener('scan_complete', (e) => {
    const data = JSON.parse(e.data);
    state.isScanning = false;
    stopElapsedTimer();
    updateLauncherUI(false);
    updateHUD();
    addLogEntry(`Mission finished! Subdomains: ${data.subdomain_count}, Hosts: ${data.live_host_count}, Vulns: ${data.finding_count}`, 'success');
    showToast(`Mission completed successfully!`, 'success');
    if (state.activeSessionId) {
      loadSessionResults(state.activeSessionId);
    }
  });

  evtSource.addEventListener('scan_cancelled', (e) => {
    state.isScanning = false;
    stopElapsedTimer();
    // Transition all active/waiting nodes to CANCELLED state visually
    Object.keys(state.nodeStatuses).forEach(nid => {
      const st = state.nodeStatuses[nid];
      if (st && (st.status === 'RUNNING' || st.status === 'WAITING')) {
        st.status = 'CANCELLED';
        st.message = 'Aborted';
        updateNodeInCanvas(nid, 'CANCELLED', st.item_count, 'Aborted');
      }
    });
    updateLauncherUI(false);
    updateHUD();
    addLogEntry('Mission aborted by operator signal.', 'warning');
    showToast('Mission aborted', 'warning');
    if (state.activeSessionId) {
      loadSessionResults(state.activeSessionId);
    }
  });

  evtSource.addEventListener('scan_error', (e) => {
    const data = JSON.parse(e.data);
    state.isScanning = false;
    stopElapsedTimer();
    updateLauncherUI(false);
    updateHUD();
    addLogEntry(`Mission execution error: ${data.error}`, 'error');
    showToast(`Error: ${data.error}`, 'error');
  });

  evtSource.onerror = () => {
    // Standard SSE browser reconnect
  };
}

function updateScanStatus(statusData) {
  state.isScanning = Boolean(statusData.is_scanning);
  state.activeSessionId = statusData.active_session_id || state.activeSessionId;
  state.activeTarget = statusData.active_target || state.activeTarget;
  
  if (statusData.node_statuses) {
    state.nodeStatuses = { ...state.nodeStatuses, ...statusData.node_statuses };
  }

  if (statusData.is_scanning) {
    state.elapsedSeconds = statusData.elapsed_seconds || 0;
    startElapsedTimer();
    updateLauncherUI(true);

    if (statusData.nodes && statusData.nodes.length > 0) {
      state.nodes = statusData.nodes;
      state.edges = normalizeEdges(statusData.edges || []);
      renderCanvas();
      setTimeout(fitCanvasToView, 60);
    } else if (statusData.active_session_id) {
      loadSessionGraph(statusData.active_session_id);
    }
    updateHUD();
  } else {
    updateLauncherUI(false);
    if (statusData.active_session_id) {
      loadSessionResults(statusData.active_session_id);
    }
  }
}

/* ==========================================================================
   Header Mission Selector & Custom Dropdown (Replaces Cockpit Button)
   High-UX Fast Switching, Live Filter, Direct Cockpit Launching
   ========================================================================== */

function initHeaderMissionSelector() {
  const wrapper = document.getElementById('mission-selector-wrapper');
  const trigger = document.getElementById('btn-header-mission-picker');
  const dropdown = document.getElementById('dropdown-mission-selector');
  const filterInput = document.getElementById('input-dropdown-filter');
  const btnCockpit = document.getElementById('btn-dropdown-open-cockpit');

  if (!wrapper || !trigger || !dropdown) return;

  function toggleDropdown() {
    const isOpen = dropdown.classList.contains('show');
    if (isOpen) {
      closeDropdown();
    } else {
      openDropdown();
    }
  }

  async function openDropdown() {
    dropdown.classList.add('show');
    trigger.classList.add('open');
    trigger.setAttribute('aria-expanded', 'true');
    
    // Refresh sessions if needed
    if (!state.sessions || state.sessions.length === 0) {
      try {
        const res = await fetch('/api/sessions');
        if (res.ok) {
          state.sessions = await res.json();
        }
      } catch (e) {}
    }
    populateHeaderMissionDropdown(state.sessions);

    if (filterInput) {
      filterInput.value = '';
      setTimeout(() => filterInput.focus(), 50);
    }
  }

  function closeDropdown() {
    dropdown.classList.remove('show');
    trigger.classList.remove('open');
    trigger.setAttribute('aria-expanded', 'false');
  }
  window.closeMissionDropdown = closeDropdown;

  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleDropdown();
  });

  // Prevent dropdown menu clicks from bubbling and closing
  dropdown.addEventListener('click', (e) => {
    e.stopPropagation();
  });

  // Click outside closes
  document.addEventListener('click', (e) => {
    if (!wrapper.contains(e.target)) {
      closeDropdown();
    }
  });

  // Filter input typing
  if (filterInput) {
    filterInput.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      filterHeaderMissions(q);
    });
  }

  // Dropdown header "Purge" button
  const btnPurgeAll = document.getElementById('btn-dropdown-purge-all');
  if (btnPurgeAll) {
    btnPurgeAll.addEventListener('click', (e) => {
      e.stopPropagation();
      closeDropdown();
      confirmPurgeAllMissions();
    });
  }

  // Dropdown footer "Launch Fresh Mission (Cockpit)"
  if (btnCockpit) {
    btnCockpit.addEventListener('click', () => {
      closeDropdown();
      openLaunchpadModal();
    });
  }
}

function updateHeaderMissionTrigger(session) {
  const targetEl = document.getElementById('header-mission-target');
  const statsEl = document.getElementById('header-mission-stats');
  if (!targetEl) return;

  if (!session) {
    targetEl.textContent = 'Select Mission...';
    if (statsEl) {
      statsEl.textContent = '--';
      statsEl.style.display = 'none';
    }
    return;
  }

  targetEl.textContent = session.target || session.id;
  targetEl.title = `${session.target || session.id} (${session.id || ''})`;

  if (statsEl) {
    statsEl.style.display = 'inline-block';
    const vulns = session.findings || 0;
    const subs = session.subdomains || 0;
    if (vulns > 0) {
      statsEl.textContent = `${subs} subs • ${vulns} vulns`;
      statsEl.style.background = 'rgba(245, 158, 11, 0.15)';
      statsEl.style.color = 'var(--color-amber)';
      statsEl.style.borderColor = 'rgba(245, 158, 11, 0.3)';
    } else if (subs > 0) {
      statsEl.textContent = `${subs} subs`;
      statsEl.style.background = 'rgba(29, 161, 255, 0.12)';
      statsEl.style.color = 'var(--color-primary)';
      statsEl.style.borderColor = 'rgba(29, 161, 255, 0.25)';
    } else {
      statsEl.textContent = session.status || 'READY';
      statsEl.style.background = 'rgba(255, 255, 255, 0.05)';
      statsEl.style.color = 'var(--text-muted)';
      statsEl.style.borderColor = 'var(--border-subtle)';
    }
  }
}

function populateHeaderMissionDropdown(sessions) {
  const listEl = document.getElementById('dropdown-missions-list');
  const countEl = document.getElementById('dropdown-missions-count');
  if (!listEl) return;

  const list = sessions || state.sessions || [];
  if (countEl) {
    countEl.textContent = `${list.length} Recorded`;
  }

  if (list.length === 0) {
    listEl.innerHTML = `
      <div class="mission-dropdown-empty">
        <svg viewBox="0 0 24 24" class="svg-icon" style="width:28px; height:28px; color:var(--text-dim);"><use href="#icon-radar"/></svg>
        <span>No reconnaissance missions recorded yet.</span>
      </div>
    `;
    return;
  }

  listEl.innerHTML = list.map(s => {
    const isActive = s.id === state.activeSessionId;
    const subs = s.subdomains || 0;
    const vulns = s.findings || 0;
    const hosts = s.live_hosts || 0;
    const status = s.status || 'COMPLETED';

    return `
      <div class="mission-item-card ${isActive ? 'active' : ''}" onclick="selectMission('${escapeHtml(s.id)}')" data-target="${escapeHtml((s.target || '').toLowerCase())}" data-id="${escapeHtml(s.id.toLowerCase())}">
        <div class="mission-item-main">
          <div class="mission-item-icon-box" title="${status}">
            <svg viewBox="0 0 24 24" class="svg-icon"><use href="#icon-radar"/></svg>
          </div>
          <div class="mission-item-details">
            <span class="mission-item-target">${escapeHtml(s.target || s.id)}</span>
            <div class="mission-item-submeta">
              <span class="mission-item-id">${escapeHtml(s.id)}</span>
              <span>&bull;</span>
              <span>${status}</span>
            </div>
          </div>
        </div>
        <div class="mission-item-metrics">
          ${subs > 0 ? `<span class="mission-metric-badge subs-active">${subs} subs</span>` : ''}
          ${vulns > 0 ? `<span class="mission-metric-badge vulns-active">${vulns} vulns</span>` : ''}
          ${isActive ? `
            <svg viewBox="0 0 24 24" class="svg-icon mission-active-check" title="Active Mission">
              <path d="M20 6L9 17l-5-5" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          ` : ''}
          <button type="button" class="btn-mission-card-delete" onclick="event.stopPropagation(); confirmDeleteMission('${escapeHtml(s.id)}', '${escapeHtml(s.target || s.id)}')" title="Delete mission">
            <svg viewBox="0 0 24 24" class="svg-icon"><use href="#icon-trash"/></svg>
          </button>
        </div>
      </div>
    `;
  }).join('');
}

function filterHeaderMissions(query) {
  const listEl = document.getElementById('dropdown-missions-list');
  if (!listEl) return;
  const cards = listEl.querySelectorAll('.mission-item-card');
  let visibleCount = 0;

  cards.forEach(card => {
    const target = card.getAttribute('data-target') || '';
    const id = card.getAttribute('data-id') || '';
    const matches = target.includes(query) || id.includes(query);
    card.style.display = matches ? 'flex' : 'none';
    if (matches) visibleCount++;
  });

  const existingEmpty = listEl.querySelector('.filter-empty-msg');
  if (visibleCount === 0 && query) {
    if (!existingEmpty) {
      const msg = document.createElement('div');
      msg.className = 'mission-dropdown-empty filter-empty-msg';
      msg.innerHTML = `<span>No missions matching "<strong>${escapeHtml(query)}</strong>"</span>`;
      listEl.appendChild(msg);
    }
  } else if (existingEmpty) {
    existingEmpty.remove();
  }
}

window.selectMission = async function(sessionId) {
  const session = (state.sessions || []).find(s => s.id === sessionId);
  if (!session) return;

  state.activeSessionId = session.id;
  state.activeTarget = session.target;

  updateHeaderMissionTrigger(session);
  if (window.closeMissionDropdown) window.closeMissionDropdown();

  // Highlight active card in dropdown
  const listEl = document.getElementById('dropdown-missions-list');
  if (listEl) {
    listEl.querySelectorAll('.mission-item-card').forEach(card => {
      card.classList.toggle('active', card.getAttribute('data-id') === session.id.toLowerCase());
    });
  }

  // Update target input if available
  const inputTarget = document.getElementById('input-target');
  if (inputTarget) inputTarget.value = session.target;

  await loadSessionGraph(session.id);
  await loadSessionResults(session.id);

  // Sync findings tab selector if present
  const findingsSelect = document.getElementById('select-findings-session');
  if (findingsSelect && findingsSelect.value !== session.id) {
    findingsSelect.value = session.id;
  }

  showToast(`Mission active: ${session.target}`, 'info');
};

/* ==========================================================================
   Mission Control & Target Launch
   ========================================================================== */

function initMissionBar() {
  const form = document.getElementById('form-mission-launch');
  const input = document.getElementById('input-target');
  const chip = document.getElementById('target-validation-chip');
  const btnStop = document.getElementById('btn-mission-stop');

  const updateTargetChip = () => {
    const val = input.value.trim();
    if (!val) {
      chip.textContent = 'READY';
      chip.className = 'target-chip';
    } else if (isValidTarget(val)) {
      chip.textContent = 'VALID ✓';
      chip.className = 'target-chip valid';
    } else {
      chip.textContent = 'DOMAIN';
      chip.className = 'target-chip';
    }
  };

  input.addEventListener('input', updateTargetChip);
  input.addEventListener('keyup', updateTargetChip);
  input.addEventListener('change', updateTargetChip);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = input.value.trim();
    if (!target) return;

    const workflow = document.getElementById('select-workflow').value;
    const profile = document.getElementById('select-profile').value;

    launchMission(target, workflow, profile);
  });

  btnStop.addEventListener('click', async () => {
    btnStop.disabled = true;
    btnStop.innerHTML = `<span class="stop-dot pulse"></span> Aborting...`;
    showToast('Abort signal dispatched to engine...', 'warning');
    addLogEntry('Abort signal dispatched to engine...', 'warning');
    try {
      const res = await fetch('/api/scan/stop', { method: 'POST' });
      const data = await res.json();
      if (data.status === 'not_running') {
        state.isScanning = false;
        stopElapsedTimer();
        updateLauncherUI(false);
      }
    } catch (err) {
      showToast(`Error stopping scan: ${err.message}`, 'error');
      btnStop.disabled = false;
      btnStop.innerHTML = `<svg viewBox="0 0 24 24" class="svg-icon btn-svg"><use href="#icon-stop"/></svg><span>Abort Mission</span>`;
    }
  });
}

async function launchMission(target, workflow, profile) {
  try {
    const skipList = Array.from(state.disabledTools);
    const res = await fetch('/api/scan/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target,
        workflow,
        profile,
        skip_tools: skipList,
      })
    });
    const data = await res.json();
    if (data.error) {
      showToast(data.error, 'error');
    } else {
      showToast(`Target dispatched: ${target}`, 'success');
      switchTab('canvas');
    }
  } catch (err) {
    showToast(`Failed to dispatch mission: ${err.message}`, 'error');
  }
}

function isValidTarget(target) {
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(target) ||
         /^(https?:\/\/)/.test(target);
}

function updateLauncherUI(isScanning) {
  const btnLaunch = document.getElementById('btn-mission-launch');
  const btnStop = document.getElementById('btn-mission-stop');
  const inputTarget = document.getElementById('input-target');
  const selectWorkflow = document.getElementById('select-workflow');
  const selectProfile = document.getElementById('select-profile');
  const telemetryPill = document.getElementById('telemetry-status-pill');
  const telemetryText = document.getElementById('telemetry-status-text');

  if (isScanning) {
    btnLaunch.style.display = 'none';
    btnStop.style.display = 'inline-flex';
    btnStop.disabled = false;
    btnStop.innerHTML = `<svg viewBox="0 0 24 24" class="svg-icon btn-svg"><use href="#icon-stop"/></svg><span>Abort Mission</span>`;
    if (inputTarget) {
      if (state.activeTarget) inputTarget.value = state.activeTarget;
      inputTarget.disabled = true;
    }
    if (selectWorkflow) selectWorkflow.disabled = true;
    if (selectProfile) selectProfile.disabled = true;
    telemetryPill.classList.add('active');
    telemetryText.textContent = 'SCANNING';
  } else {
    btnLaunch.style.display = 'inline-flex';
    btnStop.style.display = 'none';
    btnStop.disabled = false;
    btnStop.innerHTML = `<svg viewBox="0 0 24 24" class="svg-icon btn-svg"><use href="#icon-stop"/></svg><span>Abort Mission</span>`;
    if (inputTarget) inputTarget.disabled = false;
    if (selectWorkflow) selectWorkflow.disabled = false;
    if (selectProfile) selectProfile.disabled = false;
    telemetryPill.classList.remove('active');
    telemetryText.textContent = 'STANDBY';
  }
}

function startElapsedTimer() {
  stopElapsedTimer();
  const timerElem = document.getElementById('telemetry-timer');
  const startTime = Date.now() - (state.elapsedSeconds * 1000);

  state.elapsedTimer = setInterval(() => {
    const elapsed = Math.max(0, Date.now() - startTime);
    const mins = Math.floor(elapsed / 60000);
    const secs = Math.floor((elapsed % 60000) / 1000);
    const ms = Math.floor((elapsed % 1000) / 100);
    timerElem.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}.${ms}`;
  }, 100);
}

function stopElapsedTimer() {
  if (state.elapsedTimer) {
    clearInterval(state.elapsedTimer);
    state.elapsedTimer = null;
  }
}

/* ==========================================================================
   Visual DAG Canvas Rendering (Topological Native SVG Graph)
   ========================================================================== */

function initCanvasControls() {
  const container = document.getElementById('canvas-container');
  const viewport = document.getElementById('canvas-viewport');
  const btnZoomIn = document.getElementById('btn-zoom-in');
  const btnZoomOut = document.getElementById('btn-zoom-out');
  const btnZoomReset = document.getElementById('btn-zoom-reset');
  const btnZoomFit = document.getElementById('btn-zoom-fit');
  const btnCloseDrawer = document.getElementById('btn-drawer-close');

  container.addEventListener('mousedown', (e) => {
    if (e.target.closest('.dag-node') || e.target.closest('.canvas-controls') || e.target.closest('.node-drawer')) return;
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
    const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
    state.scale = Math.min(Math.max(0.35, state.scale * zoomFactor), 2.5);
    applyCanvasTransform();
  }, { passive: false });

  btnZoomIn.addEventListener('click', () => {
    state.scale = Math.min(2.5, state.scale * 1.2);
    applyCanvasTransform();
  });

  btnZoomOut.addEventListener('click', () => {
    state.scale = Math.max(0.35, state.scale / 1.2);
    applyCanvasTransform();
  });

  btnZoomReset.addEventListener('click', () => {
    state.scale = 1;
    state.panX = 80;
    state.panY = 80;
    applyCanvasTransform();
  });

  btnZoomFit.addEventListener('click', () => {
    fitCanvasToView();
  });

  btnCloseDrawer.addEventListener('click', () => {
    closeNodeDrawer();
  });

  document.getElementById('btn-copy-drawer-log').addEventListener('click', () => {
    const text = document.getElementById('drawer-log-content').textContent;
    copyToClipboard(text, 'Node console log copied');
  });
}

function applyCanvasTransform() {
  const viewport = document.getElementById('canvas-viewport');
  viewport.style.transform = `translate(${state.panX}px, ${state.panY}px) scale(${state.scale})`;
}

function normalizeEdges(rawEdges) {
  if (!Array.isArray(rawEdges)) return [];
  return rawEdges.map(e => ({
    from: e.source || e.from,
    to: e.target || e.to,
    sourcePort: e.source_port || e.sourcePort || 'out',
    targetPort: e.target_port || e.targetPort || 'in'
  })).filter(e => e.from && e.to);
}

const STAGE_ORDER = {
  'target_input': 0,
  'scope_guard': 1,
  'subfinder': 2,
  'assetfinder': 2,
  'amass': 2,
  'subenum': 2,
  'union_dedupe': 3,
  'merge': 3,
  'dnsx': 4,
  'naabu': 5,
  'httpx': 5,
  'gau': 6,
  'waybackurls': 6,
  'linkfinder': 6,
  'katana': 6,
  'nuclei': 7,
  'dalfox': 7
};

const STAGE_METADATA = [
  { id: 0, title: 'Scope Ingestion', label: 'TARGET' },
  { id: 1, title: 'Boundary Guard', label: 'SCOPE' },
  { id: 2, title: 'OSINT Discovery', label: 'OSINT' },
  { id: 3, title: 'Aggregation', label: 'DEDUPE' },
  { id: 4, title: 'DNS Resolution', label: 'DNS' },
  { id: 5, title: 'Active Probing', label: 'PROBE' },
  { id: 6, title: 'Deep Crawling', label: 'CRAWL' },
  { id: 7, title: 'Vulnerabilities', label: 'VULN' }
];

function getNodeCategory(pluginId) {
  const p = (pluginId || '').toLowerCase();
  if (p === 'target_input' || p === 'scope_guard') return 'TARGET';
  if (p.includes('subfinder') || p.includes('assetfinder') || p.includes('amass') || p.includes('subenum')) return 'OSINT';
  if (p.includes('union_dedupe') || p.includes('merge')) return 'DEDUPE';
  if (p.includes('dnsx')) return 'DNS';
  if (p.includes('httpx') || p.includes('naabu')) return 'PROBE';
  if (p.includes('katana') || p.includes('gau') || p.includes('waybackurls') || p.includes('linkfinder')) return 'CRAWL';
  if (p.includes('nuclei') || p.includes('dalfox')) return 'VULN';
  return 'BUILTIN';
}

function getNodeSubtitle(id) {
  const map = {
    'target_input': 'Ingestion & Seed Normalization',
    'scope_guard': 'Wildcard & In-Scope Filter',
    'subfinder': 'Passive DNS OSINT Enumeration',
    'assetfinder': 'Subdomain Reconnaissance',
    'amass': 'Active & Archive Discovery',
    'subenum': 'Multi-Engine Passive Aggregator',
    'union_dedupe': 'Fast Dedupe & Normalizer',
    'dnsx': 'Multi-threaded DNS Prober',
    'naabu': 'Fast Port Scanner & Service Probe',
    'httpx': 'HTTP Prober & Tech Fingerprinter',
    'gau': 'Get All URLs & Wayback Miner',
    'waybackurls': 'Historical Archive URL Mine',
    'katana': 'Next-Gen Dynamic Web Crawler',
    'nuclei': 'Vulnerability & Template Engine',
    'dalfox': 'Parameter Analysis & XSS Scanner'
  };
  return map[id] || 'Cosmic Reconnaissance Worker';
}

function fitCanvasToView() {
  const container = document.getElementById('canvas-container');
  if (!container || state.nodes.length === 0) return;

  const nodeIds = Object.keys(state.currentLayout || {});
  if (nodeIds.length === 0) return;

  let minX = Infinity, maxX = -Infinity;
  let minY = Infinity, maxY = -Infinity;

  nodeIds.forEach(id => {
    const p = state.currentLayout[id];
    if (p.x < minX) minX = p.x;
    if (p.x + 240 > maxX) maxX = p.x + 240;
    if (p.y < minY) minY = p.y;
    if (p.y + 104 > maxY) maxY = p.y + 104;
  });

  const padX = 100;
  const padY = 100;
  const graphW = (maxX - minX) + padX * 2;
  const graphH = (maxY - minY) + padY * 2;

  const drawer = document.getElementById('node-drawer');
  const drawerOffset = (drawer && drawer.classList.contains('open')) ? 380 : 0;
  const contW = Math.max(600, (container.clientWidth || 1400) - drawerOffset);
  const contH = container.clientHeight || 750;

  const scale = Math.min(Math.max(contW / graphW, 0.35), Math.max(contH / graphH, 0.35), 1.05);
  state.scale = scale;
  state.panX = Math.round((contW - (maxX + minX) * scale) / 2);
  state.panY = Math.round((contH - (maxY + minY) * scale) / 2);
  applyCanvasTransform();
}

window.panToStage = function(stageIdx) {
  const container = document.getElementById('canvas-container');
  const targetX = 80 + (stageIdx * 340);
  const contW = container.clientWidth || 1400;
  state.panX = Math.round(contW / 2 - (targetX + 120) * state.scale);
  applyCanvasTransform();
};

function renderCanvas() {
  const nodeLayer = document.getElementById('canvas-node-layer');
  const phaseLayer = document.getElementById('canvas-phase-layer');
  const svgLayer = document.getElementById('canvas-svg-layer');

  nodeLayer.innerHTML = '';
  if (phaseLayer) phaseLayer.innerHTML = '';
  const defs = svgLayer.querySelector('defs');
  svgLayer.innerHTML = '';
  if (defs) svgLayer.appendChild(defs);

  if (state.nodes.length === 0) {
    nodeLayer.innerHTML = `
      <div style="position:absolute; top:40%; left:50%; transform:translate(-50%, -50%); text-align:center; color:var(--text-dim);">
        <div style="font-size:16px; font-weight:700; color:var(--text-muted); margin-bottom:8px;">Studio Canvas Ready</div>
        <div>Launch a mission or pick a preset above to stream the execution graph.</div>
      </div>
    `;
    updateHUD();
    return;
  }

  // Ensure edges are normalized
  state.edges = normalizeEdges(state.edges);

  // Topological Level Calculation
  const { layout, tierInfo } = computeHierarchicalLayout(state.nodes, state.edges);
  state.currentLayout = layout;

  // Render Phase Lanes behind nodes
  if (phaseLayer) {
    tierInfo.forEach((tier, idx) => {
      const laneEl = document.createElement('div');
      laneEl.className = 'phase-lane';
      laneEl.style.left = `${tier.x - 20}px`;
      laneEl.style.width = '300px';

      const meta = STAGE_METADATA[tier.stageId] || { title: `Phase ${idx + 1}`, label: `STAGE ${idx + 1}` };
      laneEl.innerHTML = `
        <div class="phase-lane-header">
          <span class="phase-idx">${idx + 1}</span>
          <span>${meta.title}</span>
        </div>
      `;
      phaseLayer.appendChild(laneEl);
    });
  }

  // Calculate top clearance corridor to avoid intersecting intermediate nodes
  const allCardYs = Object.values(layout).map(p => p.y);
  const minCardY = allCardYs.length > 0 ? Math.min(...allCardYs) : 120;

  // Render SVG Edges (Intelligent Corridor Routing with Arrowheads and Flow)
  state.edges.forEach((edge, edgeIdx) => {
    const fromPos = layout[edge.from];
    const toPos = layout[edge.to];
    if (!fromPos || !toPos) return;

    const startX = fromPos.x + 240;
    const startY = fromPos.y + 53;
    const endX = toPos.x - 2;
    const endY = toPos.y + 53;

    const tierDiff = (toPos.tier !== undefined && fromPos.tier !== undefined) 
      ? (toPos.tier - fromPos.tier) 
      : Math.round((endX - startX) / 340);

    let d = '';

    if (tierDiff > 1) {
      // Non-adjacent / skip-level edge: Route via Overhead Bypass Corridor to avoid slicing through intermediate cards
      const corridorY = Math.max(55, minCardY - 45 - ((edgeIdx % 3) * 14));
      const r = 24;
      const x1 = startX + 40;
      const x2 = endX - 40;

      d = `M ${startX} ${startY} ` +
          `C ${startX + 25} ${startY}, ${x1 - r} ${corridorY}, ${x1} ${corridorY} ` +
          `L ${x2} ${corridorY} ` +
          `C ${x2 + r} ${corridorY}, ${endX - 25} ${endY}, ${endX} ${endY}`;
    } else {
      // Standard adjacent tier: Smooth cubic Bezier from port-out to port-in
      const deltaX = Math.max(45, (endX - startX) * 0.52);
      d = `M ${startX} ${startY} C ${startX + deltaX} ${startY}, ${endX - deltaX} ${endY}, ${endX} ${endY}`;
    }

    const fromStatus = (state.nodeStatuses[edge.from]?.status || 'WAITING').toUpperCase();
    const toStatus = (state.nodeStatuses[edge.to]?.status || 'WAITING').toUpperCase();
    const isEdgeActive = fromStatus === 'RUNNING' || toStatus === 'RUNNING';
    const isEdgeCompleted = (fromStatus === 'COMPLETED' || fromStatus === 'SUCCESS') && 
                            (toStatus === 'COMPLETED' || toStatus === 'SUCCESS');
    const isEdgeFailed = fromStatus === 'FAILED' || toStatus === 'FAILED';

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    
    let edgeClasses = 'canvas-edge';
    let markerId = 'arrow-default';

    if (isEdgeActive) {
      edgeClasses += ' active';
      markerId = 'arrow-active';
    } else if (isEdgeCompleted) {
      edgeClasses += ' completed';
      markerId = 'arrow-completed';
    } else if (isEdgeFailed) {
      edgeClasses += ' failed';
      markerId = 'arrow-failed';
    }

    path.setAttribute('class', edgeClasses);
    path.setAttribute('marker-end', `url(#${markerId})`);
    path.id = `edge-${edge.from}-${edge.to}`;
    svgLayer.appendChild(path);

    // Active Particle Flow Bead
    if (isEdgeActive) {
      const bead = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      bead.id = `bead-${edge.from}-${edge.to}`;
      bead.setAttribute('r', '4');
      bead.setAttribute('fill', '#00e5ff');
      bead.setAttribute('filter', 'drop-shadow(0 0 6px #00e5ff)');
      const anim = document.createElementNS('http://www.w3.org/2000/svg', 'animateMotion');
      anim.setAttribute('dur', tierDiff > 1 ? '2.2s' : '1.2s');
      anim.setAttribute('repeatCount', 'indefinite');
      anim.setAttribute('path', d);
      bead.appendChild(anim);
      svgLayer.appendChild(bead);
    }
  });

  // Render Node DOM Cards with Port Pins and Status
  state.nodes.forEach(node => {
    const pos = layout[node.id] || { x: 80, y: 80 };
    const nodeStatus = state.nodeStatuses[node.id] || { status: 'WAITING', item_count: 0 };
    const isDisabled = state.disabledTools.has(node.id) || state.disabledTools.has(node.plugin_id);
    const displayStatus = isDisabled ? 'DISABLED' : nodeStatus.status;

    const el = document.createElement('div');
    el.className = `dag-node state-${displayStatus.toLowerCase()}${isDisabled ? ' state-disabled' : ''}${state.selectedNodeId === node.id ? ' selected' : ''}`;
    el.id = `node-${node.id}`;
    el.style.left = `${pos.x}px`;
    el.style.top = `${pos.y}px`;

    const category = getNodeCategory(node.plugin_id || node.id);
    const categoryClass = `tag-${category.toLowerCase()}`;
    const subtitle = getNodeSubtitle(node.id);

    el.innerHTML = `
      <div class="node-port port-in" title="Input Port"></div>
      <div class="node-port port-out" title="Output Port"></div>
      
      <div class="dag-node-header">
        <span class="dag-node-tag ${categoryClass}">${category}</span>
        <div class="dag-node-status">
          <span class="status-dot"></span>
          <span class="status-text">${displayStatus}</span>
        </div>
      </div>
      
      <div class="dag-node-title" title="${escapeHtml(node.id)}">${escapeHtml(node.id)}</div>
      <div class="dag-node-desc">${escapeHtml(subtitle)}</div>
      
      <div class="dag-node-footer">
        <span class="dag-node-tool">${escapeHtml(node.plugin_id || 'built-in')}</span>
        <span class="dag-node-metric" id="metric-${node.id}">
          ${isDisabled ? 'Stealth Skip' : (nodeStatus.item_count ? (nodeStatus.item_count.toLocaleString() + ' items') : 'Ready')}
        </span>
      </div>
    `;

    el.addEventListener('click', (e) => {
      e.stopPropagation();
      selectNode(node.id);
    });

    nodeLayer.appendChild(el);
  });

  updateHUD();
  applyCanvasTransform();
}

function computeHierarchicalLayout(nodes, edges) {
  const adj = {};
  const inDegree = {};
  nodes.forEach(n => {
    adj[n.id] = [];
    inDegree[n.id] = 0;
  });

  edges.forEach(e => {
    if (adj[e.from]) adj[e.from].push(e.to);
    if (inDegree[e.to] !== undefined) inDegree[e.to]++;
  });

  // Topological rank computation with stage affinity
  const ranks = {};
  const queue = nodes.filter(n => inDegree[n.id] === 0).map(n => n.id);
  queue.forEach(id => {
    ranks[id] = STAGE_ORDER[id] !== undefined ? STAGE_ORDER[id] : 0;
  });

  while (queue.length > 0) {
    const curr = queue.shift();
    const currRank = ranks[curr] || 0;

    (adj[curr] || []).forEach(neighbor => {
      const minStageRank = STAGE_ORDER[neighbor] !== undefined ? STAGE_ORDER[neighbor] : (currRank + 1);
      ranks[neighbor] = Math.max(ranks[neighbor] || 0, currRank + 1, minStageRank);
      inDegree[neighbor]--;
      if (inDegree[neighbor] === 0) queue.push(neighbor);
    });
  }

  // Fallback for unvisited nodes
  nodes.forEach(n => {
    if (ranks[n.id] === undefined) {
      ranks[n.id] = STAGE_ORDER[n.id] !== undefined ? STAGE_ORDER[n.id] : 0;
    }
  });

  // Compact ranks into dense sequential columns 0, 1, 2, ...
  const uniqueRanks = [...new Set(Object.values(ranks))].sort((a, b) => a - b);
  const rankToTier = {};
  uniqueRanks.forEach((r, idx) => {
    rankToTier[r] = idx;
  });

  const tierGroups = {};
  uniqueRanks.forEach((_, idx) => {
    tierGroups[idx] = [];
  });

  nodes.forEach(n => {
    const rawRank = ranks[n.id];
    const tier = rankToTier[rawRank];
    tierGroups[tier].push(n.id);
  });

  // Calculate layout coordinates
  const layout = {};
  const CARD_WIDTH = 240;
  const CARD_HEIGHT = 104;
  const COL_WIDTH = 340;
  const ROW_GAP = 134;

  const maxNodesInCol = Math.max(...Object.values(tierGroups).map(g => g.length), 1);
  const canvasHeight = Math.max(680, maxNodesInCol * ROW_GAP + 160);

  const tierInfo = [];

  Object.keys(tierGroups).forEach(tierStr => {
    const tierIdx = parseInt(tierStr, 10);
    const group = tierGroups[tierIdx];
    const colHeight = group.length * ROW_GAP;
    const startY = 120 + Math.max(0, (canvasHeight - 120 - colHeight) / 2);
    const colX = 80 + (tierIdx * COL_WIDTH);

    tierInfo.push({
      tier: tierIdx,
      stageId: uniqueRanks[tierIdx],
      x: colX,
      nodeCount: group.length
    });

    group.forEach((nodeId, idx) => {
      layout[nodeId] = {
        x: colX,
        y: startY + (idx * ROW_GAP),
        width: CARD_WIDTH,
        height: CARD_HEIGHT,
        tier: tierIdx
      };
    });
  });

  return { layout, tierInfo };
}

function syncCanvasEdges() {
  const svgLayer = document.getElementById('canvas-svg-layer');
  state.edges.forEach(edge => {
    const edgeElem = document.getElementById(`edge-${edge.from}-${edge.to}`);
    if (!edgeElem) return;

    const fromStatus = (state.nodeStatuses[edge.from]?.status || 'WAITING').toUpperCase();
    const toStatus = (state.nodeStatuses[edge.to]?.status || 'WAITING').toUpperCase();

    const isRunning = fromStatus === 'RUNNING' || toStatus === 'RUNNING';
    const isCompleted = (fromStatus === 'COMPLETED' || fromStatus === 'SUCCESS') &&
                        (toStatus === 'COMPLETED' || toStatus === 'SUCCESS');
    const isFailed = fromStatus === 'FAILED' || toStatus === 'FAILED';

    edgeElem.classList.toggle('active', isRunning);
    edgeElem.classList.toggle('completed', !isRunning && isCompleted);
    edgeElem.classList.toggle('failed', !isRunning && !isCompleted && isFailed);

    const marker = isRunning ? 'arrow-active' : (isCompleted ? 'arrow-completed' : (isFailed ? 'arrow-failed' : 'arrow-default'));
    edgeElem.setAttribute('marker-end', `url(#${marker})`);

    // Toggle live flowing bead animation along edge
    const beadId = `bead-${edge.from}-${edge.to}`;
    let bead = document.getElementById(beadId);
    if (isRunning) {
      if (!bead && svgLayer) {
        bead = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        bead.id = beadId;
        bead.setAttribute('r', '4');
        bead.setAttribute('fill', '#00e5ff');
        bead.setAttribute('filter', 'drop-shadow(0 0 6px #00e5ff)');
        const anim = document.createElementNS('http://www.w3.org/2000/svg', 'animateMotion');
        const d = edgeElem.getAttribute('d');
        const isLong = d && d.includes('L');
        anim.setAttribute('dur', isLong ? '2.2s' : '1.2s');
        anim.setAttribute('repeatCount', 'indefinite');
        anim.setAttribute('path', d);
        bead.appendChild(anim);
        svgLayer.appendChild(bead);
      }
    } else if (bead) {
      bead.remove();
    }
  });
}

function updateNodeInCanvas(nodeId, status, itemCount, message) {
  const el = document.getElementById(`node-${nodeId}`);
  if (el) {
    el.className = `dag-node state-${status.toLowerCase()}${state.selectedNodeId === nodeId ? ' selected' : ''}`;
    const statusText = el.querySelector('.status-text');
    if (statusText) statusText.textContent = status;

    const metricElem = document.getElementById(`metric-${nodeId}`);
    if (metricElem) {
      if (status === 'RUNNING') {
        metricElem.innerHTML = `<span class="metric-pulsing">Running...</span>`;
      } else if (itemCount !== undefined && itemCount !== null) {
        metricElem.textContent = `${itemCount.toLocaleString()} items`;
      } else if (message) {
        metricElem.textContent = message;
      }
    }
  }

  syncCanvasEdges();
  updateHUD();
}

window.updateNodeInCanvas = updateNodeInCanvas;
window.syncCanvasEdges = syncCanvasEdges;

function selectNode(nodeId) {
  state.selectedNodeId = nodeId;
  document.querySelectorAll('.dag-node').forEach(n => {
    n.classList.toggle('selected', n.id === `node-${nodeId}`);
  });

  // Highlight connecting edges
  document.querySelectorAll('.canvas-edge').forEach(e => {
    e.classList.remove('selected-highlight');
  });

  state.edges.forEach(edge => {
    if (edge.from === nodeId || edge.to === nodeId) {
      const edgeElem = document.getElementById(`edge-${edge.from}-${edge.to}`);
      if (edgeElem) edgeElem.classList.add('selected-highlight');
    }
  });

  openNodeDrawer(nodeId);
}

function openNodeDrawer(nodeId) {
  const drawer = document.getElementById('node-drawer');
  drawer.classList.add('open');
  updateDrawerContent(nodeId);
  loadNodeLogs(nodeId);
}

function closeNodeDrawer() {
  const drawer = document.getElementById('node-drawer');
  drawer.classList.remove('open');
  state.selectedNodeId = null;
  document.querySelectorAll('.dag-node').forEach(n => n.classList.remove('selected'));
  document.querySelectorAll('.canvas-edge').forEach(e => e.classList.remove('selected-highlight'));
}

function updateDrawerContent(nodeId) {
  const node = state.nodes.find(n => n.id === nodeId);
  const status = state.nodeStatuses[nodeId] || { status: 'WAITING', item_count: 0 };

  document.getElementById('drawer-node-name').textContent = nodeId;
  document.getElementById('drawer-node-type').textContent = node ? (node.plugin_id || 'built-in engine') : 'stage worker';
  document.getElementById('drawer-node-status').textContent = status.status;
  document.getElementById('drawer-node-yield').textContent = `${(status.item_count || 0).toLocaleString()} items`;
  document.getElementById('drawer-node-elapsed').textContent = status.elapsed ? `${status.elapsed}s` : '--';

  // Render clickable upstream and downstream dependency pills
  const upstream = state.edges.filter(e => e.to === nodeId).map(e => e.from);
  const downstream = state.edges.filter(e => e.from === nodeId).map(e => e.to);

  const predContainer = document.getElementById('drawer-predecessors');
  const succContainer = document.getElementById('drawer-successors');

  if (predContainer) {
    if (upstream.length === 0) {
      predContainer.innerHTML = `<span class="text-dim">Root Entrypoint</span>`;
    } else {
      predContainer.innerHTML = upstream.map(u => `
        <button class="dep-pill" onclick="selectNode('${escapeHtml(u)}')">← ${escapeHtml(u)}</button>
      `).join('');
    }
  }

  if (succContainer) {
    if (downstream.length === 0) {
      succContainer.innerHTML = `<span class="text-dim">Terminal Stage</span>`;
    } else {
      succContainer.innerHTML = downstream.map(d => `
        <button class="dep-pill" onclick="selectNode('${escapeHtml(d)}')">→ ${escapeHtml(d)}</button>
      `).join('');
    }
  }
}

async function loadNodeLogs(nodeId) {
  const logBox = document.getElementById('drawer-log-content');
  logBox.textContent = `Streaming logs for [${nodeId}]...\n`;

  if (!state.activeSessionId) return;

  try {
    const res = await fetch(`/api/session/${state.activeSessionId}/logs/${nodeId}`);
    if (res.ok) {
      const data = await res.json();
      logBox.textContent = data.logs || 'No log buffer output recorded yet for this stage.';
    }
  } catch (err) {
    logBox.textContent = `Error fetching stage logs: ${err.message}`;
  }
}

function appendDrawerLog(message) {
  const logBox = document.getElementById('drawer-log-content');
  logBox.textContent += `\n${message}`;
  logBox.scrollTop = logBox.scrollHeight;
}

function updateHUD() {
  const nodeCountElem = document.getElementById('hud-node-count');
  const targetElem = document.getElementById('hud-target-name');
  if (nodeCountElem) {
    const running = Object.values(state.nodeStatuses).filter(s => s.status === 'RUNNING').length;
    const completed = Object.values(state.nodeStatuses).filter(s => s.status === 'COMPLETED' || s.status === 'SUCCESS').length;
    let text = `${state.nodes.length} Nodes • ${state.edges.length} Edges`;
    if (state.isScanning) {
      text += ` • ${running} Running • ${completed} Done`;
    }
    nodeCountElem.textContent = text;
  }
  if (targetElem) {
    targetElem.textContent = state.activeTarget || 'Ready';
  }
}

/* ==========================================================================
   Findings & Surface Explorer
   ========================================================================== */

async function loadFindingsTab() {
  await populateFindingsSessionSelector();
  if (state.activeSessionId) {
    await loadSessionResults(state.activeSessionId);
  }
}

async function populateFindingsSessionSelector() {
  const select = document.getElementById('select-findings-session');
  if (!select) return;

  try {
    const res = await fetch('/api/sessions');
    if (!res.ok) return;
    const sessions = await res.json();
    state.sessions = sessions;

    if (!sessions || sessions.length === 0) {
      select.innerHTML = '<option value="">No missions recorded</option>';
      return;
    }

    // Default to active session, or first session with findings/subdomains
    if (!state.activeSessionId) {
      const best = sessions.find(s => (s.findings || 0) > 0 || (s.subdomains || 0) > 0) || sessions[0];
      state.activeSessionId = best.id;
      state.activeTarget = best.target;
    }

    select.innerHTML = sessions.map(s => {
      const isSelected = s.id === state.activeSessionId;
      const findingsCount = s.findings || 0;
      const subsCount = s.subdomains || 0;
      return `<option value="${escapeHtml(s.id)}" ${isSelected ? 'selected' : ''}>
        ${escapeHtml(s.target)} • ${escapeHtml(s.id)} (${findingsCount} vulns, ${subsCount} subs)
      </option>`;
    }).join('');

    if (!select.dataset.bound) {
      select.dataset.bound = 'true';
      select.addEventListener('change', async (e) => {
        const sid = e.target.value;
        if (!sid) return;
        state.activeSessionId = sid;
        const s = state.sessions.find(item => item.id === sid);
        if (s) {
          state.activeTarget = s.target;
          updateHeaderMissionTrigger(s);
        }
        await loadSessionResults(sid);
        await loadSessionGraph(sid);
        showToast(`Loaded results for ${s ? s.target : sid}`, 'info');
      });
    }
  } catch (err) {
    console.error('Failed to populate session selector:', err);
  }
}

async function loadSessionResults(sessionId) {
  try {
    const res = await fetch(`/api/session/${sessionId}/results`);
    if (!res.ok) return;
    const data = await res.json();
    state.currentResults = data;
    renderFindings(data);
  } catch (err) {
    console.error('Failed to load session results:', err);
  }
}

function renderFindings(results) {
  const subdomains = results.subdomains || [];
  const hosts = results.live_hosts || [];
  const vulns = results.findings || [];

  document.getElementById('stat-subdomains-count').textContent = subdomains.length;
  document.getElementById('stat-hosts-count').textContent = hosts.length;
  document.getElementById('stat-vulns-count').textContent = vulns.length;
  document.getElementById('nav-count-findings').textContent = vulns.length + hosts.length;
  document.getElementById('badge-vulns-count').textContent = `${vulns.length} detected`;
  document.getElementById('badge-hosts-count').textContent = `${hosts.length} endpoints`;

  // Render Vulnerabilities Table
  const tbodyVulns = document.getElementById('tbody-vulns');
  if (vulns.length === 0) {
    tbodyVulns.innerHTML = `<tr><td colspan="4" class="empty-state-cell">No security vulnerabilities detected for this session.</td></tr>`;
  } else {
    tbodyVulns.innerHTML = vulns.map(v => {
      if (!v) return '';
      if (typeof v === 'string') {
        return `
          <tr>
            <td><span class="badge-sev info">INFO</span></td>
            <td>
              <div style="font-weight:600; color:var(--text-main); font-size:13px;">Security Finding</div>
              <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-dim); margin-top:2px;">${escapeHtml(v)}</div>
            </td>
            <td><span class="text-dim" style="font-family:var(--font-mono); font-size:12px;">${escapeHtml(v)}</span></td>
            <td><span class="text-dim" style="font-size:11px;">--</span></td>
          </tr>
        `;
      }
      const templateId = v['template-id'] || v.template_id || 'security-finding';
      const name = v.info?.name || v.title || templateId;
      const severity = (v.info?.severity || v.severity || 'info').toLowerCase();
      const matchedAt = v['matched-at'] || v.matched_at || v.url || v.host || '';
      const href = matchedAt ? (matchedAt.startsWith('http://') || matchedAt.startsWith('https://') ? matchedAt : `https://${matchedAt}`) : '#';
      const curlCmd = v['curl-command'] || v.curl_command || '';
      const matcher = v['matcher-name'] ? `<span class="badge-tag">${escapeHtml(v['matcher-name'])}</span>` : '';

      return `
        <tr>
          <td><span class="badge-sev ${severity}">${severity.toUpperCase()}</span></td>
          <td>
            <div style="font-weight:600; color:var(--text-main); font-size:13px;">${escapeHtml(name)}</div>
            <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-dim); display:flex; align-items:center; gap:6px; margin-top:2px;">
              <span>${escapeHtml(templateId)}</span>
              ${matcher}
            </div>
          </td>
          <td>
            <a href="${escapeHtml(href)}" target="_blank" rel="noreferrer" style="color:var(--color-primary); font-family:var(--font-mono); font-size:12px; text-decoration:none; word-break:break-all;">
              ${escapeHtml(matchedAt || '—')}
            </a>
          </td>
          <td>
            ${curlCmd ? `<button class="btn-tiny" onclick="copyCurl(${JSON.stringify(curlCmd).replace(/"/g, '&quot;')})">Copy cURL</button>` : `<span class="text-dim" style="font-size:11px;">--</span>`}
          </td>
        </tr>
      `;
    }).join('');
  }

  // Render Live Endpoints Table
  const tbodyHosts = document.getElementById('tbody-hosts');
  if (hosts.length === 0) {
    tbodyHosts.innerHTML = `<tr><td colspan="4" class="empty-state-cell">No live endpoints probed yet.</td></tr>`;
  } else {
    tbodyHosts.innerHTML = hosts.map(h => {
      const code = h.status_code || 200;
      const codeGroup = `s${Math.floor(code / 100)}xx`;
      return `
        <tr>
          <td><a href="${escapeHtml(h.url)}" target="_blank" rel="noreferrer" style="color:var(--color-primary); text-decoration:none; font-family:var(--font-mono); font-size:12px;">${escapeHtml(h.url)}</a></td>
          <td><span class="status-code-pill ${codeGroup}">${code}</span></td>
          <td>${escapeHtml(h.title || h.tech || 'HTTP Endpoint')}</td>
          <td>
            <button class="btn-tiny" onclick="copyToClipboard('${escapeHtml(h.url)}', 'URL copied')">Copy URL</button>
          </td>
        </tr>
      `;
    }).join('');
  }

  // Render Subdomains Table
  const tbodySubs = document.getElementById('tbody-subdomains');
  if (subdomains.length === 0) {
    tbodySubs.innerHTML = `<tr><td colspan="3" class="empty-state-cell">No subdomains discovered yet.</td></tr>`;
  } else {
    tbodySubs.innerHTML = subdomains.map(s => {
      const fqdn = typeof s === 'string' ? s : (s.fqdn || s.host || '');
      const source = typeof s === 'string' ? 'verified' : (s.source || 'recon');
      return `
        <tr>
          <td><strong style="color:var(--text-main); font-family:var(--font-mono); font-size:12px;">${escapeHtml(fqdn)}</strong></td>
          <td><span style="font-family:var(--font-mono); font-size:11px; color:var(--text-dim);">${escapeHtml(source)}</span></td>
          <td>
            <button class="btn-tiny" onclick="copyToClipboard('${escapeHtml(fqdn)}', 'Domain copied')">Copy</button>
          </td>
        </tr>
      `;
    }).join('');
  }

  // Attach search filter listener
  const inputSearch = document.getElementById('input-search-findings');
  if (inputSearch && !inputSearch.dataset.bound) {
    inputSearch.dataset.bound = 'true';
    inputSearch.addEventListener('input', (e) => {
      const q = e.target.value.toLowerCase().trim();
      filterTableRows('tbody-vulns', q);
      filterTableRows('tbody-hosts', q);
      filterTableRows('tbody-subdomains', q);
    });
  }

  // Attach copy all subdomains listener
  const btnCopySubs = document.getElementById('btn-copy-all-subdomains');
  if (btnCopySubs && !btnCopySubs.dataset.bound) {
    btnCopySubs.dataset.bound = 'true';
    btnCopySubs.addEventListener('click', () => {
      const subs = state.currentResults?.subdomains || [];
      if (subs.length === 0) return showToast('No subdomains to copy', 'warning');
      const text = subs.map(s => typeof s === 'string' ? s : (s.fqdn || s.host || '')).join('\n');
      copyToClipboard(text, `${subs.length} subdomains copied to clipboard!`);
    });
  }
}

function filterTableRows(tbodyId, query) {
  const tbody = document.getElementById(tbodyId);
  if (!tbody) return;
  const rows = tbody.querySelectorAll('tr');
  rows.forEach(r => {
    if (r.querySelector('.empty-state-cell')) return;
    const text = r.innerText.toLowerCase();
    r.style.display = text.includes(query) ? '' : 'none';
  });
}

window.copyCurl = function(cmd) {
  if (!cmd) {
    showToast('No curl command available for this finding', 'warning');
    return;
  }
  copyToClipboard(cmd, 'cURL command copied to clipboard');
};

/* ==========================================================================
   Live Terminal Stream Controller
   ========================================================================== */

function initTerminalActions() {
  const checkAutoScroll = document.getElementById('check-auto-scroll');
  const btnClear = document.getElementById('btn-clear-logs');
  const btnCopy = document.getElementById('btn-copy-terminal');

  checkAutoScroll.addEventListener('change', () => {
    state.autoScrollTerminal = checkAutoScroll.checked;
  });

  btnClear.addEventListener('click', () => {
    document.getElementById('console-log-stream').innerHTML = '';
    showToast('Terminal buffer cleared', 'success');
  });

  btnCopy.addEventListener('click', () => {
    const text = document.getElementById('console-log-stream').innerText;
    copyToClipboard(text, 'Terminal logs copied to clipboard');
  });

  document.getElementById('btn-export-json').addEventListener('click', () => {
    if (!state.activeSessionId) return showToast('No active session to export', 'warning');
    window.open(`/api/session/${state.activeSessionId}/export/json`, '_blank');
  });

  document.getElementById('btn-export-csv').addEventListener('click', () => {
    if (!state.activeSessionId) return showToast('No active session to export', 'warning');
    window.open(`/api/session/${state.activeSessionId}/export/csv`, '_blank');
  });

  document.getElementById('btn-copy-ai-prompt').addEventListener('click', async () => {
    if (!state.activeSessionId) return showToast('No active session to generate prompt', 'warning');
    try {
      const res = await fetch(`/api/session/${state.activeSessionId}/export/ai`);
      if (res.ok) {
        const text = await res.text();
        copyToClipboard(text, 'AI Distillation Prompt copied to clipboard!');
      } else {
        showToast('AI prompt bundle not found for this session', 'warning');
      }
    } catch (err) {
      showToast(`Export error: ${err.message}`, 'error');
    }
  });

  document.getElementById('btn-copy-all-subdomains').addEventListener('click', () => {
    const subs = (state.currentResults.subdomains || []).map(s => s.fqdn || s).join('\n');
    if (!subs) return showToast('No subdomains to copy', 'warning');
    copyToClipboard(subs, `${state.currentResults.subdomains.length} subdomains copied`);
  });

  const searchInput = document.getElementById('input-search-findings');
  searchInput.addEventListener('input', () => {
    const q = searchInput.value.toLowerCase().trim();
    filterFindingsRows(q);
  });
}

function filterFindingsRows(query) {
  const rows = document.querySelectorAll('.data-table tbody tr');
  rows.forEach(row => {
    if (row.classList.contains('empty-state-cell')) return;
    const text = row.innerText.toLowerCase();
    row.style.display = (!query || text.includes(query)) ? '' : 'none';
  });
}

function addLogEntry(message, level = 'info', timestamp = null) {
  const stream = document.getElementById('console-log-stream');
  const timeStr = timestamp ? timestamp.split('T')[1].slice(0, 8) : new Date().toTimeString().slice(0, 8);

  const entry = document.createElement('div');
  entry.className = 'log-entry';
  entry.innerHTML = `
    <span class="log-time">${timeStr}</span>
    <span class="log-level ${(level || 'info').toLowerCase()}">${(level || 'SYS').toUpperCase()}</span>
    <span class="log-text">${escapeHtml(message)}</span>
  `;

  stream.appendChild(entry);
  if (state.autoScrollTerminal) {
    stream.scrollTop = stream.scrollHeight;
  }
}

/* ==========================================================================
   Sessions Archive Explorer
   ========================================================================== */

async function loadSessions() {
  const tbody = document.getElementById('tbody-sessions');
  tbody.innerHTML = `<tr><td colspan="6" class="empty-state-cell">Loading missions...</td></tr>`;

  // Bind toolbar buttons once
  const btnRefresh = document.getElementById('btn-refresh-sessions');
  if (btnRefresh && !btnRefresh.dataset.bound) {
    btnRefresh.dataset.bound = 'true';
    btnRefresh.addEventListener('click', loadSessions);
  }
  const btnClearAll = document.getElementById('btn-clear-all-sessions');
  if (btnClearAll && !btnClearAll.dataset.bound) {
    btnClearAll.dataset.bound = 'true';
    btnClearAll.addEventListener('click', confirmPurgeAllMissions);
  }

  try {
    const res = await fetch('/api/sessions');
    if (!res.ok) throw new Error('API error');
    const sessions = await res.json();
    state.sessions = sessions;
    populateHeaderMissionDropdown(sessions);

    if (sessions.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-state-cell">No historical sessions recorded yet. Launch your first reconnaissance mission!</td></tr>`;
      return;
    }

    tbody.innerHTML = sessions.map(s => `
      <tr>
        <td><strong style="color:var(--color-primary);">${escapeHtml(s.id)}</strong></td>
        <td><strong>${escapeHtml(s.target)}</strong></td>
        <td><span class="badge-sev ${s.status === 'COMPLETED' ? 'low' : 'info'}">${s.status}</span></td>
        <td><span style="font-family:var(--font-mono); font-size:11px;">${s.subdomains || s.subdomain_count || 0} subs &bull; ${s.live_hosts || s.host_count || 0} hosts</span></td>
        <td style="color:var(--text-dim); font-size:11px;">${escapeHtml(s.started_at || s.created_at || '')}</td>
        <td>
          <div style="display:flex; align-items:center; gap:6px;">
            <button class="btn-tiny" onclick="inspectSession('${s.id}')">Inspect Canvas</button>
            <button class="btn-tiny" onclick="window.open('/api/session/${s.id}/export/json', '_blank')">JSON</button>
            <button class="btn-tiny btn-danger-icon" onclick="confirmDeleteMission('${s.id}', '${escapeHtml(s.target)}')" title="Delete mission history">
              <svg viewBox="0 0 24 24" class="svg-icon"><use href="#icon-trash"/></svg>
            </button>
          </div>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state-cell">Failed to load missions: ${err.message}</td></tr>`;
  }
}

window.inspectSession = async function(sessionId) {
  state.activeSessionId = sessionId;
  const s = (state.sessions || []).find(item => item.id === sessionId);
  if (s) {
    state.activeTarget = s.target;
    updateHeaderMissionTrigger(s);
  }
  await loadSessionGraph(sessionId);
  await loadSessionResults(sessionId);
  switchTab('canvas');
  showToast(`Loaded session: ${sessionId}`, 'success');
};

async function loadSessionGraph(sessionId) {
  try {
    const res = await fetch(`/api/session/${sessionId}`);
    if (res.ok) {
      const data = await res.json();
      const wf = data.workflow || {};
      state.nodes = wf.nodes || data.nodes || [];
      state.edges = normalizeEdges(wf.edges || data.edges || []);
      state.activeTarget = data.target;

      if (data.checkpoints) {
        if (!state.isScanning) {
          state.nodeStatuses = {};
        }
        Object.entries(data.checkpoints).forEach(([nid, cp]) => {
          let itemCount = 0;
          if (cp.outputs) {
            Object.values(cp.outputs).forEach(out => {
              if (out.lines) itemCount += out.lines;
            });
          }
          state.nodeStatuses[nid] = {
            ...(state.nodeStatuses[nid] || {}),
            status: cp.status,
            item_count: itemCount,
            elapsed: cp.duration_seconds ? cp.duration_seconds.toFixed(1) : null,
            error: cp.error
          };
        });
      }
      renderCanvas();
      setTimeout(fitCanvasToView, 50);
    }
  } catch (err) {
    console.error('Failed to load session graph:', err);
  }
}

/* ==========================================================================
   Feature B: Arsenal Doctor & Scoped Plugin Hub
   ========================================================================== */

async function loadDoctorData() {
  try {
    const [sysRes, pluginsRes, cfgRes] = await Promise.all([
      fetch('/api/system').then(r => r.ok ? r.json() : null).catch(() => null),
      fetch('/api/plugins').then(r => r.ok ? r.json() : null).catch(() => null),
      fetch('/api/plugins/config').then(r => r.ok ? r.json() : null).catch(() => null)
    ]);
    
    if (sysRes) {
      document.getElementById('sys-os').textContent = `${sysRes.os_name || sysRes.os || 'Linux'} (${sysRes.arch || 'x86_64'})`;
      document.getElementById('sys-python').textContent = `Python ${sysRes.python_version || sysRes.python || '3.11'}`;
      document.getElementById('sys-go').textContent = sysRes.go_version || (sysRes.go_installed ? 'Installed' : 'Go 1.22');
    }

    if (cfgRes) {
      const currentScope = state.pluginScope;
      let disabledList = cfgRes.disabled_tools || [];
      if (currentScope === 'project' && state.activeWorkspace.id in (cfgRes.project_overrides || {})) {
        disabledList = cfgRes.project_overrides[state.activeWorkspace.id].disabled_tools || [];
      }
      state.disabledTools = new Set(disabledList);
    }

    if (sysRes && sysRes.tools) {
      const grid = document.getElementById('tools-grid');
      const rawTools = sysRes.tools || {};
      const tools = Object.entries(rawTools).map(([name, data]) => ({
        name,
        installed: !!data.installed,
        version: data.version,
        path: data.path
      }));

      if (pluginsRes && Array.isArray(pluginsRes.plugins)) {
        pluginsRes.plugins.forEach(p => {
          if (!tools.some(t => t.name.toLowerCase() === p.name.toLowerCase())) {
            tools.push({
              name: p.name,
              installed: true,
              version: p.version || '1.0.0',
              path: `Plugin (${p.stage})`
            });
          }
        });
      }

      const installedCount = tools.filter(t => t.installed).length;
      document.getElementById('sys-tools-count').textContent = `${installedCount} / ${tools.length} Installed`;

      grid.innerHTML = tools.map(t => {
        const isToolDisabled = state.disabledTools.has(t.name.toLowerCase());
        const isChecked = !isToolDisabled;

        return `
          <div class="tool-card ${isToolDisabled ? 'disabled' : ''}" id="tool-card-${t.name}">
            <div class="tool-card-header">
              <span class="tool-name">${escapeHtml(t.name)}</span>
              <div style="display:flex; align-items:center; gap:8px;">
                <label class="cyber-switch" title="${isChecked ? 'Click to deactivate tool' : 'Click to activate tool'}">
                  <input type="checkbox" ${isChecked ? 'checked' : ''} onchange="toggleToolActivation('${escapeHtml(t.name)}', this.checked)">
                  <span class="cyber-slider"></span>
                </label>
                <span class="tool-badge-status ${t.installed ? 'installed' : 'missing'}">
                  ${isToolDisabled ? 'STEALTH OFF' : (t.installed ? 'ACTIVE ✓' : 'MISSING')}
                </span>
              </div>
            </div>
            <div class="tool-meta">
              <span>Version: ${escapeHtml(t.version || 'Unknown')}</span>
              <span class="tool-path" title="${escapeHtml(t.path || 'Not on PATH')}">${escapeHtml(t.path || 'Managed / Standard')}</span>
            </div>
          </div>
        `;
      }).join('');
    }
  } catch (err) {
    console.error('Failed to load doctor diagnostics:', err);
  }
}

window.toggleToolActivation = async function(toolName, isEnabled) {
  const toolId = toolName.toLowerCase();
  if (isEnabled) {
    state.disabledTools.delete(toolId);
  } else {
    state.disabledTools.add(toolId);
  }

  // Update card visual state
  const card = document.getElementById(`tool-card-${toolName}`);
  if (card) {
    card.classList.toggle('disabled', !isEnabled);
    const badge = card.querySelector('.tool-badge-status');
    if (badge) {
      badge.textContent = isEnabled ? 'ACTIVE ✓' : 'STEALTH OFF';
    }
  }

  // Persist to backend
  try {
    await fetch('/api/plugins/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool_id: toolId,
        enabled: isEnabled,
        scope: state.pluginScope,
        project_id: state.activeWorkspace.id,
      })
    });
    showToast(`${toolName} ${isEnabled ? 'activated' : 'deactivated (stealth skip)'}`, isEnabled ? 'success' : 'warning');
    renderCanvas();
  } catch (err) {
    showToast(`Failed to update ${toolName}: ${err.message}`, 'error');
  }
};

/* ==========================================================================
   Feature A: Mission Launchpad Modal & Cockpit
   ========================================================================== */

function initLaunchpadModal() {
  const btnOpen = document.getElementById('btn-open-launchpad');
  const btnClose = document.getElementById('btn-close-launchpad-modal');
  const btnSkip = document.getElementById('btn-launchpad-skip');
  const checkStartup = document.getElementById('check-skip-launchpad-startup');
  const formQuick = document.getElementById('form-launchpad-quick');

  if (btnOpen) btnOpen.addEventListener('click', openLaunchpadModal);
  btnClose.addEventListener('click', closeLaunchpadModal);
  btnSkip.addEventListener('click', () => {
    closeLaunchpadModal();
    showToast('Studio Canvas Mode active. Pick target or preset anytime.', 'info');
  });

  checkStartup.addEventListener('change', () => {
    if (checkStartup.checked) {
      localStorage.setItem('astrarecon_skip_launchpad', 'true');
    } else {
      localStorage.removeItem('astrarecon_skip_launchpad');
    }
  });

  formQuick.addEventListener('submit', (e) => {
    e.preventDefault();
    const target = document.getElementById('launchpad-input-target').value.trim();
    if (!target) return;
    const workflow = document.getElementById('launchpad-select-workflow').value;
    closeLaunchpadModal();
    document.getElementById('input-target').value = target;
    document.getElementById('select-workflow').value = workflow;
    launchMission(target, workflow, 'auto');
  });

  // Check if startup launchpad should be opened
  const shouldSkip = localStorage.getItem('astrarecon_skip_launchpad') === 'true';
  if (!shouldSkip && !state.isScanning) {
    setTimeout(openLaunchpadModal, 300);
  }
}

async function openLaunchpadModal() {
  const modal = document.getElementById('modal-launchpad');
  modal.style.display = 'flex';
  await loadRecentEngagements();
}

function closeLaunchpadModal() {
  document.getElementById('modal-launchpad').style.display = 'none';
}

async function loadRecentEngagements() {
  const grid = document.getElementById('launchpad-recent-grid');
  const countElem = document.getElementById('launchpad-recent-count');

  try {
    const res = await fetch('/api/projects/recent');
    const contentType = res.headers.get('content-type') || '';
    if (!res.ok || !contentType.includes('application/json')) {
      throw new Error(`Server returned status ${res.status}`);
    }
    const data = await res.json();
    const recents = data.recent_targets || [];

    countElem.textContent = `${recents.length} Available`;

    if (recents.length === 0) {
      grid.innerHTML = `
        <div style="grid-column:1/-1; padding:24px 16px; text-align:center; color:var(--text-dim); background:var(--bg-elevated); border:1px dashed var(--border-subtle); border-radius:var(--radius-md);">
          <div style="margin-bottom:8px; font-weight:600; color:var(--text-main);">No Previous Missions Recorded</div>
          <div style="font-size:12px; color:var(--text-muted);">Enter a target domain below to launch your first reconnaissance run!</div>
        </div>
      `;
      return;
    }

    grid.innerHTML = recents.map(r => `
      <div class="recent-mission-card">
        <div class="recent-mission-top">
          <span class="recent-target-title">${escapeHtml(r.target)}</span>
          <span class="badge-sev ${r.status === 'COMPLETED' ? 'low' : 'info'}">${r.status}</span>
        </div>
        <div class="recent-metrics-strip">
          <span>${r.subdomains || 0} subs</span> &bull;
          <span>${r.live_hosts || 0} hosts</span> &bull;
          <span style="color:var(--color-rose);">${r.findings || 0} vulns</span>
        </div>
        <div class="recent-actions-row">
          <button class="btn-primary-gradient" style="height:28px; padding:0 10px; font-size:11px;" onclick="quickRescanTarget('${escapeHtml(r.target)}')">
            Re-scan ↻
          </button>
          <button class="btn-tiny" onclick="quickInspectSession('${r.session_id}')">
            Inspect Canvas ↗
          </button>
          <button class="btn-tiny btn-danger-icon" onclick="event.stopPropagation(); confirmDeleteMission('${r.session_id}', '${escapeHtml(r.target)}')" title="Delete mission history">
            <svg viewBox="0 0 24 24" class="svg-icon"><use href="#icon-trash"/></svg>
          </button>
        </div>
      </div>
    `).join('');
  } catch (err) {
    grid.innerHTML = `
      <div style="grid-column:1/-1; padding:20px; text-align:center; background:var(--bg-elevated); border:1px solid var(--border-subtle); border-radius:var(--radius-md);">
        <div style="color:var(--text-muted); font-size:12px; margin-bottom:8px;">No recent engagements synced yet or server initializing.</div>
        <div style="font-size:11px; color:var(--text-dim);">Enter a target below to start fresh.</div>
      </div>
    `;
  }
}

window.quickRescanTarget = function(target) {
  closeLaunchpadModal();
  document.getElementById('input-target').value = target;
  launchMission(target, 'default', 'auto');
};

window.quickInspectSession = async function(sessionId) {
  closeLaunchpadModal();
  inspectSession(sessionId);
};

/* ==========================================================================
   Feature C: Workspace / Project Management
   ========================================================================== */

function initWorkspaceModal() {
  const btnSelect = document.getElementById('btn-workspace-select');
  const btnClose = document.getElementById('btn-close-workspaces-modal');
  const formCreate = document.getElementById('form-create-workspace');

  btnSelect.addEventListener('click', openWorkspaceModal);
  btnClose.addEventListener('click', closeWorkspaceModal);

  formCreate.addEventListener('submit', async (e) => {
    e.preventDefault();
    const nameInput = document.getElementById('input-new-workspace-name');
    const name = nameInput.value.trim();
    if (!name) return;

    try {
      const res = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, target: '' })
      });
      const data = await res.json();
      nameInput.value = '';
      showToast(`Workspace "${name}" created!`, 'success');
      await loadWorkspaces();
    } catch (err) {
      showToast(`Error creating workspace: ${err.message}`, 'error');
    }
  });
}

async function openWorkspaceModal() {
  document.getElementById('modal-workspaces').style.display = 'flex';
  await loadWorkspaces();
}

function closeWorkspaceModal() {
  document.getElementById('modal-workspaces').style.display = 'none';
}

async function loadWorkspaces() {
  const list = document.getElementById('workspace-list');
  try {
    const res = await fetch('/api/projects');
    if (!res.ok) throw new Error('API error');
    const projects = await res.json();
    state.projects = projects;

    list.innerHTML = projects.map(p => {
      const isActive = state.activeWorkspace.id === p.id;
      return `
        <div class="workspace-item ${isActive ? 'active' : ''}" onclick="switchWorkspace('${p.id}')">
          <div>
            <div class="workspace-item-title">${escapeHtml(p.name)}</div>
            <div class="workspace-item-meta">${p.target ? 'Target: ' + escapeHtml(p.target) : 'Unbound Scope'}</div>
          </div>
          <div>
            ${isActive ? '<span class="badge-sev low">ACTIVE</span>' : '<button class="btn-tiny">Switch</button>'}
          </div>
        </div>
      `;
    }).join('');
  } catch (err) {
    list.innerHTML = `<div style="color:var(--color-rose);">Failed to load workspaces: ${err.message}</div>`;
  }
}

window.switchWorkspace = function(projectId) {
  const prj = state.projects.find(p => p.id === projectId);
  if (!prj) return;

  state.activeWorkspace = prj;
  document.getElementById('workspace-active-name').textContent = prj.name;
  if (prj.target) {
    document.getElementById('input-target').value = prj.target;
  }
  closeWorkspaceModal();
  showToast(`Switched to workspace: ${prj.name}`, 'success');
  loadDoctorData();
};

/* ==========================================================================
   Feature B2: Register Custom Tool / Script Modal
   ========================================================================== */

function initCustomToolModal() {
  const btnOpen = document.getElementById('btn-open-custom-tool-modal');
  const btnClose = document.getElementById('btn-close-custom-tool-modal');
  const btnCancel = document.getElementById('btn-cancel-custom-tool');
  const form = document.getElementById('form-register-custom-tool');
  const scopeSelect = document.getElementById('select-plugin-scope');

  if (btnOpen) btnOpen.addEventListener('click', () => {
    document.getElementById('modal-custom-tool').style.display = 'flex';
  });

  if (btnClose) btnClose.addEventListener('click', closeCustomToolModal);
  if (btnCancel) btnCancel.addEventListener('click', closeCustomToolModal);

  if (scopeSelect) {
    scopeSelect.addEventListener('change', (e) => {
      state.pluginScope = e.target.value;
      loadDoctorData();
      showToast(`Plugin view changed to: ${state.pluginScope.toUpperCase()}`, 'info');
    });
  }

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('custom-tool-name').value.trim();
      const command = document.getElementById('custom-tool-cmd').value.trim();
      const inputType = document.getElementById('custom-tool-input').value;
      const outputType = document.getElementById('custom-tool-output').value;

      try {
        const res = await fetch('/api/plugins/custom', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, command, input_type: inputType, output_type: outputType })
        });
        const data = await res.json();
        if (data.error) {
          showToast(data.error, 'error');
        } else {
          closeCustomToolModal();
          showToast(`Custom tool "${name}" registered to Arsenal!`, 'success');
          loadDoctorData();
        }
      } catch (err) {
        showToast(`Registration error: ${err.message}`, 'error');
      }
    });
  }
}

function closeCustomToolModal() {
  document.getElementById('modal-custom-tool').style.display = 'none';
}

/* ==========================================================================
   Keyboard Shortcuts & Modals Controller
   ========================================================================== */

function initKeyboardShortcuts() {
  window.addEventListener('keydown', (e) => {
    if (['INPUT', 'SELECT', 'TEXTAREA'].includes(e.target.tagName)) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('form-mission-launch').dispatchEvent(new Event('submit'));
      }
      return;
    }

    if (e.key === '1') switchTab('canvas');
    if (e.key === '2') switchTab('findings');
    if (e.key === '3') switchTab('logs');
    if (e.key === '4') switchTab('sessions');
    if (e.key === '5') switchTab('doctor');

    if (e.key.toLowerCase() === 'm' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      openLaunchpadModal();
    }

    if (e.key.toLowerCase() === 't' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      toggleTheme();
    }

    if (e.key === '?' || (e.key === '/' && e.shiftKey)) {
      e.preventDefault();
      toggleShortcutsModal();
    }

    if (e.key === 'Escape') {
      closeNodeDrawer();
      closeShortcutsModal();
      closeLaunchpadModal();
      closeWorkspaceModal();
      closeCustomToolModal();
      if (window.closeMissionDropdown) window.closeMissionDropdown();
      if (window.closeDeleteConfirmationModal) window.closeDeleteConfirmationModal();
    }

    if (state.activeTab === 'canvas') {
      if (e.key === '+' || e.key === '=') document.getElementById('btn-zoom-in').click();
      if (e.key === '-') document.getElementById('btn-zoom-out').click();
      if (e.key.toLowerCase() === 'c') document.getElementById('btn-zoom-reset').click();
      if (e.key.toLowerCase() === 'f') document.getElementById('btn-zoom-fit').click();
    }
  });
}

function initModals() {
  document.getElementById('btn-shortcuts-modal').addEventListener('click', toggleShortcutsModal);
  document.getElementById('btn-close-shortcuts-modal').addEventListener('click', closeShortcutsModal);
  document.getElementById('modal-shortcuts').addEventListener('click', (e) => {
    if (e.target.id === 'modal-shortcuts') closeShortcutsModal();
  });

  initLaunchpadModal();
  initWorkspaceModal();
  initCustomToolModal();
  initDeleteConfirmationModal();
}

function toggleShortcutsModal() {
  const modal = document.getElementById('modal-shortcuts');
  modal.style.display = modal.style.display === 'none' ? 'flex' : 'none';
}

function closeShortcutsModal() {
  document.getElementById('modal-shortcuts').style.display = 'none';
}

/* ==========================================================================
   Mission & History Deletion Controller
   ========================================================================== */

let pendingDeletion = null;

function initDeleteConfirmationModal() {
  const modal = document.getElementById('modal-confirm-delete');
  const btnClose = document.getElementById('btn-close-delete-modal');
  const btnCancel = document.getElementById('btn-cancel-delete');
  const btnExecute = document.getElementById('btn-execute-delete');

  if (!modal) return;

  function closeModal() {
    modal.style.display = 'none';
    pendingDeletion = null;
  }
  window.closeDeleteConfirmationModal = closeModal;

  if (btnClose) btnClose.addEventListener('click', closeModal);
  if (btnCancel) btnCancel.addEventListener('click', closeModal);
  modal.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
  });

  if (btnExecute) {
    btnExecute.addEventListener('click', async () => {
      if (!pendingDeletion) return;
      btnExecute.disabled = true;
      const prevHtml = btnExecute.innerHTML;
      btnExecute.innerHTML = `<span>Purging...</span>`;

      try {
        if (pendingDeletion.type === 'single') {
          const sid = pendingDeletion.sessionId;
          const res = await fetch(`/api/session/${sid}`, { method: 'DELETE' });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) {
            throw new Error(data.error || `HTTP ${res.status}`);
          }

          // Remove from local sessions state
          state.sessions = (state.sessions || []).filter(s => s.id !== sid);
          showToast(`Mission deleted: ${pendingDeletion.target || sid}`, 'success');

          // If active session was deleted, switch to next available or reset
          if (state.activeSessionId === sid) {
            if (state.sessions.length > 0) {
              const nextSession = state.sessions[0];
              await selectMission(nextSession.id);
            } else {
              state.activeSessionId = null;
              state.activeTarget = null;
              updateHeaderMissionTrigger(null);
              state.nodes = [];
              state.edges = [];
              state.nodeStatuses = {};
              loadPresetPreview('default');
              const inputTarget = document.getElementById('input-target');
              if (inputTarget) inputTarget.value = '';
              const findingsSelect = document.getElementById('select-findings-session');
              if (findingsSelect) findingsSelect.innerHTML = '<option value="">No missions recorded</option>';
              renderFindingsTable([], []);
              renderSubdomainsTable([]);
              const elSubs = document.getElementById('stat-subdomains-count');
              if (elSubs) elSubs.textContent = '0';
              const elHosts = document.getElementById('stat-hosts-count');
              if (elHosts) elHosts.textContent = '0';
              const elVulns = document.getElementById('stat-vulns-count');
              if (elVulns) elVulns.textContent = '0';
              const elNav = document.getElementById('nav-count-findings');
              if (elNav) elNav.textContent = '0';
            }
          }

        } else if (pendingDeletion.type === 'bulk') {
          const res = await fetch('/api/sessions', { method: 'DELETE' });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) {
            throw new Error(data.error || `HTTP ${res.status}`);
          }

          state.sessions = [];
          state.activeSessionId = null;
          state.activeTarget = null;
          updateHeaderMissionTrigger(null);
          state.nodes = [];
          state.edges = [];
          state.nodeStatuses = {};
          loadPresetPreview('default');
          const inputTarget = document.getElementById('input-target');
          if (inputTarget) inputTarget.value = '';
          const findingsSelect = document.getElementById('select-findings-session');
          if (findingsSelect) findingsSelect.innerHTML = '<option value="">No missions recorded</option>';
          renderFindingsTable([], []);
          renderSubdomainsTable([]);
          const elSubs = document.getElementById('stat-subdomains-count');
          if (elSubs) elSubs.textContent = '0';
          const elHosts = document.getElementById('stat-hosts-count');
          if (elHosts) elHosts.textContent = '0';
          const elVulns = document.getElementById('stat-vulns-count');
          if (elVulns) elVulns.textContent = '0';
          const elNav = document.getElementById('nav-count-findings');
          if (elNav) elNav.textContent = '0';

          const count = data.deleted_count || 0;
          showToast(`Mission history purged (${count} missions removed)`, 'success');
        }

        // Refresh lists across all UI tabs
        populateHeaderMissionDropdown(state.sessions);
        if (state.activeTab === 'sessions') loadSessions();
        if (state.activeTab === 'findings') populateFindingsSessionSelector();
        loadRecentEngagements();

      } catch (err) {
        showToast(`Failed to delete: ${err.message}`, 'error');
      } finally {
        btnExecute.disabled = false;
        btnExecute.innerHTML = prevHtml;
        closeModal();
      }
    });
  }
}

window.confirmDeleteMission = function(sessionId, target) {
  const modal = document.getElementById('modal-confirm-delete');
  const title = document.getElementById('confirm-delete-title');
  const msg = document.getElementById('confirm-delete-message');
  const preview = document.getElementById('confirm-delete-target-preview');
  const targetName = document.getElementById('confirm-delete-target-name');
  const btnText = document.getElementById('btn-execute-delete-text');

  if (!modal) return;

  pendingDeletion = { type: 'single', sessionId, target };
  title.textContent = 'Delete Reconnaissance Mission';
  msg.textContent = 'Are you sure you want to permanently delete this mission? Checkpoints, scan logs, and discovery artifacts will be permanently purged from disk.';
  preview.style.display = 'block';
  targetName.textContent = `${target || sessionId} (${sessionId})`;
  btnText.textContent = 'Delete Mission';

  modal.style.display = 'flex';
};

window.confirmPurgeAllMissions = function() {
  const modal = document.getElementById('modal-confirm-delete');
  const title = document.getElementById('confirm-delete-title');
  const msg = document.getElementById('confirm-delete-message');
  const preview = document.getElementById('confirm-delete-target-preview');
  const btnText = document.getElementById('btn-execute-delete-text');

  if (!modal) return;

  const count = (state.sessions || []).length;
  pendingDeletion = { type: 'bulk' };
  title.textContent = 'Purge Mission History';
  msg.textContent = `Are you sure you want to permanently delete ALL recorded missions (${count} recorded)? All checkpoints, discovery artifacts, and reports across all targets will be permanently erased.`;
  preview.style.display = 'none';
  btnText.textContent = 'Purge All Missions';

  modal.style.display = 'flex';
};

/* ==========================================================================
   Toast Notification System & Helpers
   ========================================================================== */

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(8px)';
    toast.style.transition = 'all 0.2s ease';
    setTimeout(() => toast.remove(), 200);
  }, 2600);
}

function copyToClipboard(text, successMsg = 'Copied to clipboard') {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => showToast(successMsg, 'success'));
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    showToast(successMsg, 'success');
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

async function fetchParallel(urls) {
  return Promise.all(urls.map(url => fetch(url).then(r => r.json()).catch(() => null)));
}

const PRESET_TOPOLOGIES = {
  default: {
    nodes: [
      { id: 'target_input', plugin_id: 'builtin.target_input' },
      { id: 'scope_guard', plugin_id: 'builtin.scope_guard' },
      { id: 'subfinder', plugin_id: 'subfinder' },
      { id: 'assetfinder', plugin_id: 'assetfinder' },
      { id: 'union_dedupe', plugin_id: 'builtin.union_dedupe' },
      { id: 'dnsx', plugin_id: 'dnsx' },
      { id: 'httpx', plugin_id: 'httpx' },
      { id: 'nuclei', plugin_id: 'nuclei' },
    ],
    edges: [
      { from: 'target_input', to: 'scope_guard' },
      { from: 'scope_guard', to: 'subfinder' },
      { from: 'scope_guard', to: 'assetfinder' },
      { from: 'subfinder', to: 'union_dedupe' },
      { from: 'assetfinder', to: 'union_dedupe' },
      { from: 'union_dedupe', to: 'dnsx' },
      { from: 'dnsx', to: 'httpx' },
      { from: 'httpx', to: 'nuclei' },
    ],
  },
  fast: {
    nodes: [
      { id: 'target_input', plugin_id: 'builtin.target_input' },
      { id: 'subfinder', plugin_id: 'subfinder' },
      { id: 'dnsx', plugin_id: 'dnsx' },
      { id: 'httpx', plugin_id: 'httpx' },
    ],
    edges: [
      { from: 'target_input', to: 'subfinder' },
      { from: 'subfinder', to: 'dnsx' },
      { from: 'dnsx', to: 'httpx' },
    ],
  },
  passive: {
    nodes: [
      { id: 'target_input', plugin_id: 'builtin.target_input' },
      { id: 'subfinder', plugin_id: 'subfinder' },
      { id: 'assetfinder', plugin_id: 'assetfinder' },
      { id: 'waybackurls', plugin_id: 'waybackurls' },
    ],
    edges: [
      { from: 'target_input', to: 'subfinder' },
      { from: 'target_input', to: 'assetfinder' },
      { from: 'subfinder', to: 'waybackurls' },
    ],
  },
  vuln: {
    nodes: [
      { id: 'target_input', plugin_id: 'builtin.target_input' },
      { id: 'httpx', plugin_id: 'httpx' },
      { id: 'katana', plugin_id: 'katana' },
      { id: 'nuclei', plugin_id: 'nuclei' },
      { id: 'dalfox', plugin_id: 'dalfox' },
    ],
    edges: [
      { from: 'target_input', to: 'httpx' },
      { from: 'httpx', to: 'katana' },
      { from: 'katana', to: 'nuclei' },
      { from: 'katana', to: 'dalfox' },
    ],
  },
};

function loadPresetPreview(presetId) {
  if (state.isScanning) return;
  const topo = PRESET_TOPOLOGIES[presetId] || PRESET_TOPOLOGIES.default;
  state.nodes = topo.nodes;
  state.edges = topo.edges;
  state.nodeStatuses = {};
  renderCanvas();
}

async function loadInitialData() {
  const select = document.getElementById('select-workflow');
  select.addEventListener('change', (e) => {
    loadPresetPreview(e.target.value);
  });

  try {
    const presets = await fetch('/api/presets').then(r => r.json()).catch(() => []);
    if (presets && presets.length > 0) {
      select.innerHTML = presets.map(p => `
        <option value="${p.id}">${escapeHtml(p.name)} (${p.stages ? p.stages.length : p.node_count || 4} Stages)</option>
      `).join('');
    }
  } catch (err) {
    console.error('Initial preset fetch error:', err);
  }

  // Pre-fetch historical missions to populate header mission selector & find best active session
  try {
    const sRes = await fetch('/api/sessions');
    if (sRes.ok) {
      state.sessions = await sRes.json();
      populateHeaderMissionDropdown(state.sessions);
    }
  } catch (err) {
    console.error('Failed to pre-fetch sessions:', err);
  }

  // Handle URL query parameters (e.g. ?session_id=... & ?tab=...)
  const urlParams = new URLSearchParams(window.location.search);
  const urlSession = urlParams.get('session_id');
  const urlTab = urlParams.get('tab');

  if (urlSession) {
    state.activeSessionId = urlSession;
    await inspectSession(urlSession);
    const activeS = (state.sessions || []).find(s => s.id === urlSession);
    if (activeS) updateHeaderMissionTrigger(activeS);
    if (urlTab) switchTab(urlTab);
    return;
  }

  // Check active scan or hydrated session state on page load
  try {
    const statusRes = await fetch('/api/status').then(r => r.json()).catch(() => null);
    if (statusRes) {
      if (statusRes.is_scanning) {
        updateScanStatus(statusRes);
        if (urlTab) switchTab(urlTab);
        return;
      }
      if (statusRes.active_session_id) {
        state.activeSessionId = statusRes.active_session_id;
        state.activeTarget = statusRes.active_target;
        const activeS = (state.sessions || []).find(s => s.id === statusRes.active_session_id);
        if (activeS) updateHeaderMissionTrigger(activeS);
        loadSessionResults(statusRes.active_session_id);
      }
    }
  } catch (e) {}

  // If no active session was set by status, pick the best historical session
  if (!state.activeSessionId && state.sessions && state.sessions.length > 0) {
    const best = state.sessions.find(s => (s.findings || 0) > 0 || (s.subdomains || 0) > 0) || state.sessions[0];
    state.activeSessionId = best.id;
    state.activeTarget = best.target;
    updateHeaderMissionTrigger(best);
    const inputTarget = document.getElementById('input-target');
    if (inputTarget) inputTarget.value = best.target;
    await loadSessionGraph(best.id);
    await loadSessionResults(best.id);
  } else if (state.activeSessionId) {
    const activeS = (state.sessions || []).find(s => s.id === state.activeSessionId);
    if (activeS) updateHeaderMissionTrigger(activeS);
  } else {
    updateHeaderMissionTrigger(null);
  }

  if (urlTab) {
    switchTab(urlTab);
  }

  // Load initial preview graph if no nodes loaded
  if (state.nodes.length === 0) {
    loadPresetPreview('default');
  }
}

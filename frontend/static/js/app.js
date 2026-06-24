/* SentinelScan AI — dashboard application
 * ---------------------------------------------------------------------------
 * Single-file vanilla JS SPA. Talks to the Flask backend over fetch().
 * Charts are Chart.js v4. No build step required.
 */
'use strict';

const API = {
  async get(path) {
    const r = await fetch(path, { credentials: 'include' });
    if (r.status === 401) {
      const next = encodeURIComponent(location.pathname + location.search);
      location.replace('/login?next=' + next);
      return null;
    }
    return r.json();
  },
  async post(path, body) {
    const r = await fetch(path, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (r.status === 401) {
      const next = encodeURIComponent(location.pathname + location.search);
      location.replace('/login?next=' + next);
      return { ok: false, error: 'auth required' };
    }
    return r.json();
  },
};

const state = {
  running: false,
  mode: 'auto',
  actualMode: null,
  packetCount: 0,
  attackCount: 0,
  lastAttackIds: new Set(),
  charts: {},
  pollingHandle: null,
  isRefreshing: false,
  lastFetchAt: null,
  filters: { search: '', risk: 'all' },
  allAttacks: [],
  selectedEventIdx: 0,
  pagination: {
    limit: 100,
    offset: 0,
    hasMore: true,
    isLoadingMore: false,
  },
};

const THEME = {
  current: document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark',
  storageKey: 'sentinelscan.theme',
};

function getColors() {
  const light = THEME.current === 'light';
  return {
    risk: { low: '#10B981', medium: '#F59E0B', high: '#EF4444', critical: '#F43F5E' },
    accent: '#18B69B',
    accentSoft: 'rgba(24, 182, 155, 0.14)',
    grid: light ? 'rgba(15, 23, 42, 0.08)' : 'rgba(255, 255, 255, 0.06)',
    text: light ? '#6B7A90' : '#606B7E',
    tooltipBg: light ? 'rgba(255, 255, 255, 0.98)' : 'rgba(17, 19, 24, 0.98)',
    tooltipBorder: light ? 'rgba(14, 158, 136, 0.4)' : 'rgba(24, 182, 155, 0.28)',
    border: light ? '#F4F6FA' : '#0C0E12',
  };
}

// Back-compat alias — code that still references COLORS.grid / COLORS.text /
// COLORS.risk.* / COLORS.accent / COLORS.accentSoft keeps working.
const COLORS = new Proxy({}, {
  get(_t, prop) {
    const c = getColors();
    if (prop === 'risk') return c.risk;
    return c[prop];
  },
});

function applyChartDefaults() {
  const c = getColors();
  Chart.defaults.color = c.text;
  Chart.defaults.font.family = "Inter, system-ui, sans-serif";
  Chart.defaults.borderColor = c.grid;
}
applyChartDefaults();

// Apply a theme: write attribute, persist, refresh chart colors and tooltips
// so the very next hover reflects the new palette (no reload needed).
function applyTheme(theme) {
  THEME.current = theme;
  if (theme === 'light') document.documentElement.setAttribute('data-theme', 'light');
  else document.documentElement.removeAttribute('data-theme');
  try { localStorage.setItem(THEME.storageKey, theme); } catch (e) {}
  applyChartDefaults();
  const c = getColors();
  Object.values(state.charts).forEach((chart) => {
    if (chart.options && chart.options.plugins && chart.options.plugins.tooltip) {
      chart.options.plugins.tooltip.backgroundColor = c.tooltipBg;
      chart.options.plugins.tooltip.borderColor = c.tooltipBorder;
    }
    if (chart.options && chart.options.scales) {
      Object.values(chart.options.scales).forEach((s) => {
        if (s && s.grid) s.grid.color = c.grid;
      });
    }
    if (chart.data && chart.data.datasets) {
      chart.data.datasets.forEach((ds) => {
        const swap = (v) => (v === '#0F172A' || v === '#0F1120') ? c.border : v;
        if (Array.isArray(ds.backgroundColor)) {
          ds.backgroundColor = ds.backgroundColor.map(swap);
        } else if (typeof ds.backgroundColor === 'string') {
          ds.backgroundColor = swap(ds.backgroundColor);
        }
        if (typeof ds.borderColor === 'string') {
          ds.borderColor = swap(ds.borderColor);
        }
      });
    }
    chart.update('none');
  });
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------
const fmt = {
  time(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleTimeString();
  },
  shortTime(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  },
  relTime(iso) {
    if (!iso) return '—';
    const diff = Date.now() - new Date(iso).getTime();
    if (diff < 60_000) return `${Math.floor(diff / 1000)}s ago`;
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return `${Math.floor(diff / 86_400_000)}d ago`;
  },
  duration(seconds) {
    const s = Number(seconds || 0);
    if (s < 1) return '<1s';
    if (s < 60) return `${Math.round(s)}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
    return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  },
};

function riskPill(level) {
  return `<span class="badge badge-${level}">${level}</span>`;
}
function riskMeter(score) {
  const pct = Math.max(0, Math.min(100, score * 10));
  const cls =
    score >= 8.5 ? 'critical' :
    score >= 6.5 ? 'high' :
    score >= 4.0 ? 'medium' : 'low';
  return `<div class="risk-bar"><div class="risk-bar-fill ${cls}" style="width:${pct}%"></div></div>`;
}
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}
function setLastUpdated(refreshing, lastFetchAt) {
  const el = document.getElementById('last-updated');
  if (!el) return;
  el.classList.remove('refreshing', 'fresh');
  if (refreshing) {
    el.classList.add('refreshing');
    el.querySelector('span:last-child').textContent = 'Updating…';
    return;
  }
  if (!lastFetchAt) {
    el.querySelector('span:last-child').textContent = '—';
    return;
  }
  const diff = Date.now() - lastFetchAt;
  if (diff < 4000) el.classList.add('fresh');
  el.querySelector('span:last-child').textContent =
    diff < 60_000 ? `Updated ${Math.floor(diff / 1000)}s ago`
    : `Updated ${fmt.relTime(new Date(lastFetchAt).toISOString())}`;
}

// ---------------------------------------------------------------------------
// Charts
// ---------------------------------------------------------------------------
function initCharts() {
  state.charts.timeline = new Chart(document.getElementById('chart-timeline'), {
    type: 'bar',
    data: { labels: [], datasets: [{ label: 'Attacks', data: [], backgroundColor: COLORS.accent, borderRadius: 4, maxBarThickness: 18 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: getColors().tooltipBg,
          borderColor: getColors().tooltipBorder,
          borderWidth: 1,
          padding: 10,
          callbacks: {
            label: (ctx) => `${ctx.parsed.y} attack${ctx.parsed.y === 1 ? '' : 's'}`,
          },
        },
      },
      scales: {
        x: {
          grid: { color: COLORS.grid, drawBorder: false },
          ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 8, font: { size: 10 } },
        },
        y: {
          grid: { color: COLORS.grid, drawBorder: false },
          beginAtZero: true,
          ticks: { precision: 0, font: { size: 10 } },
        },
      },
    },
  });

  state.charts.risk = new Chart(document.getElementById('chart-risk'), {
    type: 'doughnut',
    data: {
      labels: ['Low', 'Medium', 'High', 'Critical'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: [COLORS.risk.low, COLORS.risk.medium, COLORS.risk.high, COLORS.risk.critical],
        borderColor: getColors().border,
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      animation: { duration: 300 },
      plugins: {
        legend: {
          position: 'bottom',
          labels: { boxWidth: 10, padding: 10, font: { size: 11 } },
        },
        tooltip: {
          backgroundColor: getColors().tooltipBg,
          callbacks: {
            label: (ctx) => {
              const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
              const pct = total ? ((ctx.parsed / total) * 100).toFixed(0) : 0;
              return ` ${ctx.label}: ${ctx.parsed} (${pct}%)`;
            },
          },
        },
      },
    },
  });

  state.charts.scans = new Chart(document.getElementById('chart-scans'), {
    type: 'bar',
    data: { labels: [], datasets: [{ data: [], backgroundColor: '#A78BFA', borderRadius: 4 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      animation: { duration: 300 },
      plugins: {
        legend: { display: false },
        tooltip: { backgroundColor: getColors().tooltipBg },
      },
      scales: {
        x: { grid: { color: COLORS.grid, drawBorder: false }, beginAtZero: true, ticks: { precision: 0, font: { size: 10 } } },
        y: { grid: { display: false }, ticks: { font: { size: 11 } } },
      },
    },
  });

  state.charts.tools = new Chart(document.getElementById('chart-tools'), {
    type: 'pie',
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: ['#22D3EE', '#A78BFA', '#34D399', '#F472B6', '#FBBF24', '#60A5FA', '#FB7185', '#F97316'],
        borderColor: getColors().border,
        borderWidth: 2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300 },
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 10, padding: 8, font: { size: 11 } } },
        tooltip: { backgroundColor: getColors().tooltipBg },
      },
    },
  });

  state.charts.countries = new Chart(document.getElementById('chart-countries'), {
    type: 'bar',
    data: { labels: [], datasets: [{ data: [], backgroundColor: '#FBBF24', borderRadius: 4 }] },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300 },
      plugins: {
        legend: { display: false },
        tooltip: { backgroundColor: getColors().tooltipBg },
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: {
            maxRotation: 35,
            minRotation: 0,
            autoSkip: false,
            font: { size: 10 },
            callback(value) {
              const lbl = this.getLabelForValue(value);
              return lbl.length > 10 ? lbl.slice(0, 9) + '…' : lbl;
            },
          },
        },
        y: {
          grid: { color: COLORS.grid, drawBorder: false },
          beginAtZero: true,
          ticks: { precision: 0, font: { size: 10 } },
        },
      },
    },
  });
}

// Show or hide a "Waiting for data…" overlay over a chart canvas.
// Used when the engine is running but no events have been recorded yet,
// so the user understands the empty chart isn't a bug.
function _setChartOverlay(chartId, visible, title, sub) {
  const canvas = document.getElementById(chartId);
  if (!canvas) return;
  const parent = canvas.parentElement;
  if (!parent) return;
  let overlay = parent.querySelector('.chart-empty-overlay');
  if (!visible) {
    if (overlay) overlay.remove();
    return;
  }
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.className = 'chart-empty-overlay';
    parent.appendChild(overlay);
  }
  overlay.innerHTML = `
    <div class="chart-empty-title">${escapeHtml(title)}</div>
    <div class="chart-empty-sub">${escapeHtml(sub)}</div>
  `;
}

function updateCharts(stats) {
  // Hide overlays first; we'll re-show them on the per-chart branches below
  // when the engine is running but data hasn't accumulated yet.
  const isRunning = state.running;
  const noData = (stats.total_attacks ?? 0) === 0;

  if (stats.timeline) {
    state.charts.timeline.data.labels = stats.timeline.map((t) => t.hour);
    state.charts.timeline.data.datasets[0].data = stats.timeline.map((t) => t.count);
    state.charts.timeline.update('none');
  }
  // Timeline is "empty" only if all 24 buckets are zero.
  const timelineAllZero = (stats.timeline || []).every((t) => !t.count);
  _setChartOverlay(
    'chart-timeline',
    timelineAllZero,
    isRunning ? 'Waiting for the first attacks…' : 'No attacks in the last 24 hours',
    isRunning ? 'The simulator emits attacks every few seconds.' : 'Click ▶ Start in the header to begin capture.'
  );

  if (stats.risk_distribution) {
    const r = stats.risk_distribution;
    state.charts.risk.data.datasets[0].data = [r.low || 0, r.medium || 0, r.high || 0, r.risk_critical || r.critical || 0];
    state.charts.risk.update('none');
  }
  const riskEmpty = !stats.risk_distribution || Object.values(stats.risk_distribution).every((v) => !v);
  _setChartOverlay(
    'chart-risk',
    riskEmpty,
    isRunning ? 'Waiting for the first attacks…' : 'No risk data yet',
    isRunning ? 'Distribution appears once attacks are classified.' : 'Click ▶ Start to begin.'
  );

  if (stats.scan_distribution) {
    const entries = Object.entries(stats.scan_distribution).sort((a, b) => b[1] - a[1]).slice(0, 8);
    state.charts.scans.data.labels = entries.map((e) => e[0]);
    state.charts.scans.data.datasets[0].data = entries.map((e) => e[1]);
    state.charts.scans.update('none');
  }
  const scansEmpty = !stats.scan_distribution || Object.keys(stats.scan_distribution).length === 0;
  _setChartOverlay(
    'chart-scans',
    scansEmpty,
    isRunning ? 'Waiting for the first attacks…' : 'No scan types yet',
    isRunning ? 'Classifier will populate this once it has data.' : 'Click ▶ Start to begin.'
  );

  if (stats.tool_distribution) {
    const entries = Object.entries(stats.tool_distribution).sort((a, b) => b[1] - a[1]);
    state.charts.tools.data.labels = entries.map((e) => e[0]);
    state.charts.tools.data.datasets[0].data = entries.map((e) => e[1]);
    state.charts.tools.update('none');
  }
  const toolsEmpty = !stats.tool_distribution || Object.keys(stats.tool_distribution).length === 0;
  _setChartOverlay(
    'chart-tools',
    toolsEmpty,
    isRunning ? 'Waiting for the first attacks…' : 'No tool fingerprints yet',
    isRunning ? 'Tool fingerprinting runs on each detected scan.' : 'Click ▶ Start to begin.'
  );

  if (stats.country_distribution) {
    const entries = Object.entries(stats.country_distribution).sort((a, b) => b[1] - a[1]).slice(0, 6);
    state.charts.countries.data.labels = entries.map((e) => e[0]);
    state.charts.countries.data.datasets[0].data = entries.map((e) => e[1]);
    state.charts.countries.update('none');
  }
  const countriesEmpty = !stats.country_distribution || Object.keys(stats.country_distribution).length === 0;
  _setChartOverlay(
    'chart-countries',
    countriesEmpty,
    isRunning ? 'Waiting for the first attacks…' : 'No country data yet',
    isRunning ? 'Geo enrichment runs once attackers are profiled.' : 'Click ▶ Start to begin.'
  );
}

// ---------------------------------------------------------------------------
// Render functions
// ---------------------------------------------------------------------------
function renderStatCards(stats) {
  const setText = (id, val) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (el.textContent !== String(val)) {
      el.textContent = val;
      el.classList.remove('flash-update');
      void el.offsetWidth;
      el.classList.add('flash-update');
    }
  };
  setText('stat-total', (stats.total_attacks ?? 0).toLocaleString());
  setText('stat-24h', (stats.attacks_last_24h ?? 0).toLocaleString());
  setText('stat-active', (stats.active_threats ?? 0).toLocaleString());
  setText('stat-critical', (stats.critical_attacks ?? 0).toLocaleString());
}

function renderTopSources(sources) {
  const host = document.getElementById('top-sources');
  const count = document.getElementById('top-sources-count');
  if (count) count.textContent = `${sources?.length || 0} source${(sources?.length || 0) === 1 ? '' : 's'}`;

  if (!sources || !sources.length) {
    host.innerHTML = `
      <div class="tbl-empty">
        <div class="tbl-empty-title">No top sources yet</div>
        <div>Start the engine to begin detection.</div>
      </div>`;
    return;
  }
  host.innerHTML = sources.map((s) => `
    <div style="display:flex;align-items:center;gap:12px;padding:8px 10px;border-radius:var(--r-sm);border:1px solid var(--c-border);background:var(--c-surface-2)">
      <div style="font-family:'JetBrains Mono',monospace;font-size:12.5px;font-weight:600;color:var(--c-accent-text);width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex-shrink:0">${escapeHtml(s.ip)}</div>
      <div style="flex:1;min-width:0">
        <div style="display:flex;justify-content:space-between;font-size:11.5px;color:var(--c-text-3);margin-bottom:5px">
          <span>${s.hits} hit${s.hits > 1 ? 's' : ''}</span>
          <span style="color:var(--c-text-2)">risk ${s.worst_risk.toFixed(1)}/10</span>
        </div>
        ${riskMeter(s.worst_risk)}
      </div>
    </div>
  `).join('');
}

// ---------------------------------------------------------------------------
// Attacks: filter, search, drawer
// ---------------------------------------------------------------------------
function getFilteredAttacks() {
  const q = state.filters.search.trim().toLowerCase();
  const risk = state.filters.risk;
  return state.allAttacks.filter((a) => {
    if (risk !== 'all' && a.risk_level !== risk) return false;
    if (!q) return true;
    const haystack = [
      a.source?.ip, a.source?.country, a.source?.isp, a.source?.tool_guess,
      a.scan_type, a.risk_level, a.source?.os_guess,
    ].filter(Boolean).join(' ').toLowerCase();
    return haystack.includes(q);
  });
}

let attackScrollObserver = null;

async function loadMoreAttacks() {
  if (state.pagination.isLoadingMore || !state.pagination.hasMore) return;
  state.pagination.isLoadingMore = true;
  
  const nextOffset = state.pagination.offset + state.pagination.limit;
  try {
    const attacks = await API.get(`/api/attacks?limit=${state.pagination.limit}&offset=${nextOffset}`);
    if (attacks && attacks.length > 0) {
      state.pagination.offset = nextOffset;
      const existingIds = new Set(state.allAttacks.map(a => a.id));
      const uniqueNewAttacks = attacks.filter(a => !existingIds.has(a.id));
      state.allAttacks = state.allAttacks.concat(uniqueNewAttacks);
      state.pagination.hasMore = (attacks.length === state.pagination.limit);
      renderAttacks();
    } else {
      state.pagination.hasMore = false;
    }
  } catch (err) {
    console.error('Failed to load more attacks', err);
  } finally {
    state.pagination.isLoadingMore = false;
  }
}

function initInfiniteScroll() {
  const host = document.getElementById('events-list');
  if (!host) return;

  attackScrollObserver = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        attackScrollObserver.unobserve(entry.target);
        loadMoreAttacks();
      }
    });
  }, {
    root: host,
    threshold: 0.1,
  });
}

function renderAttacks() {
  if (attackScrollObserver) {
    attackScrollObserver.disconnect();
  }
  const host = document.getElementById('events-list');
  const shownEl = document.getElementById('attacks-shown');
  const totalEl = document.getElementById('attacks-total');
  const unackedEl = document.getElementById('attacks-unacked');
  const filtered = getFilteredAttacks();
  const total = state.allAttacks.length;
  const unacked = filtered.filter((a) => !a.acknowledged_at).length;

  if (shownEl) shownEl.textContent = filtered.length;
  if (totalEl) totalEl.textContent = total;
  if (unackedEl) unackedEl.textContent = unacked;

  if (!filtered.length) {
    const msg = total === 0
      ? `<div class="event-empty-title">No events yet</div>
         <div class="event-empty-hint">Click <svg width="10" height="10" style="display:inline-block;vertical-align:-1px"><use href="#icon-play"/></svg> Start in the top bar to begin capturing traffic.</div>`
      : `<div class="event-empty-title">No matches</div>
         <div class="event-empty-hint">${total} event${total === 1 ? '' : 's'} hidden by current filters.</div>`;
    host.innerHTML = `<li class="event-empty">${msg}</li>`;
    return;
  }

  const slice = filtered;
  host.innerHTML = slice.map((a, idx) => {
    const acked = !!a.acknowledged_at;
    const level = a.risk_level || 'low';
    const score = Number(a.risk_score || 0).toFixed(1);
    const tool  = a.source?.tool_guess || '—';
    const toolConf = Number(a.source?.tool_confidence || 0).toFixed(0);

    const statusDot = acked
      ? `<span class="ev-acked" title="Acked at ${fmt.shortTime(a.acknowledged_at)}">✓</span>`
      : `<span class="ev-dot" title="Unacknowledged"></span>`;

    return `
      <li class="ev-row ${level} ${acked ? 'is-acked' : ''} ${idx === state.selectedEventIdx ? 'selected' : ''}"
          data-attack-id="${escapeHtml(a.id)}"
          data-event-index="${idx}"
          role="option"
          tabindex="${idx === state.selectedEventIdx ? 0 : -1}"
          aria-selected="${idx === state.selectedEventIdx}">
        <div class="ev-stripe ${escapeHtml(level)}"></div>
        <div class="ev-score ${escapeHtml(level)}">${score}</div>
        <div class="ev-main">
          <div class="ev-line1">
            <span class="ev-ip">${escapeHtml(a.source?.ip || '—')}</span>
            <span class="ev-sep">·</span>
            <span class="ev-scan">${escapeHtml(a.scan_type)}</span>
            <span class="ev-sep">·</span>
            <span class="ev-tool">${escapeHtml(tool)} <span class="ev-conf">${toolConf}%</span></span>
            ${statusDot}
          </div>
          <div class="ev-line2">
            <span class="ev-time">${fmt.shortTime(a.started_at)}</span>
            <span class="ev-sep">·</span>
            <span class="ev-geo">${escapeHtml(a.source?.country || '—')}</span>
            <span class="ev-isp">${escapeHtml(a.source?.isp || '')}</span>
            <span class="ev-sep">·</span>
            <span class="ev-meta">${a.unique_ports} ports · ${a.packet_count} pkts · ${fmt.duration(a.duration_seconds)}</span>
          </div>
        </div>
        <div class="ev-badge-wrap">
          <span class="badge badge-${escapeHtml(level)}">${escapeHtml(level)}</span>
        </div>
      </li>
    `;
  }).join('');

  if (attackScrollObserver && slice.length > 0 && state.pagination.hasMore) {
    const targetIdx = Math.floor(slice.length * 0.8);
    const targetEl = host.children[targetIdx];
    if (targetEl) {
      attackScrollObserver.observe(targetEl);
    }
  }
}

async function openAttackDrawer(id) {
  const drawer = document.getElementById('attack-drawer');
  const body = document.getElementById('drawer-body');
  if (!drawer || !body) return;

  drawer.style.display = 'block';
  drawer.setAttribute('aria-hidden', 'false');

  body.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:48px 0;color:var(--c-text-4);gap:10px">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="animation:spin 1s linear infinite;color:var(--c-accent)">
        <path d="M21 12a9 9 0 11-6.219-8.56"/>
      </svg>
      <style>@keyframes spin{to{transform:rotate(360deg)}}</style>
      <span style="font-size:12px">Analyzing event…</span>
    </div>
  `;

  try {
    const attack = await API.get(`/api/attacks/${id}`);
    if (!attack) {
      body.innerHTML = `<div class="text-rose-400 text-sm">Failed to load attack details.</div>`;
      return;
    }

    const pred = attack.predictions || {
      predicted_next_ports: [22, 80, 443],
      follow_up_probability: 0.5,
      explanation: 'No predictions available.'
    };

    const level = attack.risk_level || 'low';
    const score = Number(attack.risk_score || 0).toFixed(1);
    const probPct = (pred.follow_up_probability * 100).toFixed(0);
    const probColor = pred.follow_up_probability >= 0.70 ? 'text-rose-400'
                    : pred.follow_up_probability >= 0.35 ? 'text-amber-400'
                    : 'text-emerald-400';

    const probColorStyle = pred.follow_up_probability >= 0.70 ? `color:var(--c-high)` :
                           pred.follow_up_probability >= 0.35 ? `color:var(--c-medium)` :
                           `color:var(--c-low)`;

    body.innerHTML = `
      <div class="drawer-row">
        <div style="display:flex;align-items:center;justify-content:space-between">
          ${riskPill(level)}
          <span style="font-size:11px;color:var(--c-text-4)">${fmt.relTime(attack.started_at)}</span>
        </div>
      </div>

      <div class="drawer-divider"></div>

      <div class="drawer-row">
        <span class="drawer-row-label">Source IP</span>
        <span class="drawer-row-val mono" style="color:var(--c-accent-text)">${escapeHtml(attack.source?.ip || '—')}</span>
        <span style="font-size:11.5px;color:var(--c-text-3);margin-top:2px">${escapeHtml(attack.source?.country || '—')} · ${escapeHtml(attack.source?.isp || '—')}</span>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        <div class="drawer-row">
          <span class="drawer-row-label">Risk Score</span>
          <span style="font-size:20px;font-weight:700;color:var(--c-text-1);letter-spacing:-0.03em">${score}<span style="font-size:13px;font-weight:400;color:var(--c-text-3)">/10</span></span>
          ${riskMeter(attack.risk_score)}
        </div>
        <div class="drawer-row">
          <span class="drawer-row-label">Ports Hit</span>
          <span style="font-size:20px;font-weight:700;color:var(--c-text-1);font-family:'JetBrains Mono',monospace;letter-spacing:-0.03em">${attack.unique_ports}</span>
        </div>
      </div>

      <div class="drawer-row">
        <span class="drawer-row-label">Scan Type</span>
        <span class="drawer-row-val">${escapeHtml(attack.scan_type)}</span>
        <span style="font-size:11px;color:var(--c-text-4);margin-top:1px">Confidence: ${attack.scan_confidence}%</span>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        <div class="drawer-row">
          <span class="drawer-row-label">Tool</span>
          <span class="drawer-row-val mono">${escapeHtml(attack.source?.tool_guess || '—')}</span>
          <span style="font-size:11px;color:var(--c-text-4)">${(attack.source?.tool_confidence || 0).toFixed(0)}% conf.</span>
        </div>
        <div class="drawer-row">
          <span class="drawer-row-label">OS Guess</span>
          <span class="drawer-row-val">${escapeHtml(attack.source?.os_guess || '—')}</span>
        </div>
      </div>

      <div class="drawer-row">
        <span class="drawer-row-label">Started</span>
        <span class="drawer-row-val mono">${fmt.time(attack.started_at)}</span>
      </div>

      <div class="drawer-divider"></div>

      <div class="ml-block">
        <div class="ml-block-title">
          <svg width="13" height="13"><use href="#icon-cpu"/></svg>
          ML Insights
        </div>
        <div class="ml-grid">
          <div>
            <div class="ml-stat-label">Follow-up Probability</div>
            <div class="ml-stat-val" style="${probColorStyle}">${probPct}%</div>
          </div>
          <div>
            <div class="ml-stat-label">Predicted Ports</div>
            <div class="ml-stat-val" style="font-family:'JetBrains Mono',monospace;font-size:13px">${pred.predicted_next_ports.join(', ')}</div>
          </div>
        </div>
        <div class="ml-explanation">${escapeHtml(pred.explanation)}</div>
      </div>

      <button class="btn btn-danger btn-full" id="drawer-block-btn"
              style="margin-top:4px">
        Block this IP
      </button>
    `;
    drawer.style.display = 'block';
    drawer.setAttribute('aria-hidden', 'false');

    // Bug #10 fix: disable the button immediately on first click to prevent
    // double-firing simultaneous block requests.
    document.getElementById('drawer-block-btn')?.addEventListener('click', async (ev) => {
      const blockBtn = ev.currentTarget;
      if (blockBtn.disabled) return;
      blockBtn.disabled = true;
      const origText = blockBtn.textContent;
      blockBtn.textContent = 'Blocking…';
      try {
        const r = await API.post('/api/ips/block', { ip: attack.source.ip, reason: `Manual block from event ${attack.id}` });
        if (r.ok) {
          showToast({ title: 'IP Blocked', body: `${attack.source.ip} added to firewall`, level: 'success' });
          closeDrawer();
          refreshIPS();
        } else {
          showToast({ title: 'Block failed', body: r.error || 'Unknown error', level: 'error' });
          blockBtn.disabled = false;
          blockBtn.textContent = origText;
        }
      } catch (e) {
        showToast({ title: 'Network error', body: String(e), level: 'error' });
        blockBtn.disabled = false;
        blockBtn.textContent = origText;
      }
    });
  } catch (err) {
    body.innerHTML = `<div style="color:var(--c-high);font-size:12.5px;padding:12px 0">Failed to load event: ${escapeHtml(err.message)}</div>`;
  }
}

function closeDrawer() {
  const drawer = document.getElementById('attack-drawer');
  if (!drawer) return;
  drawer.style.display = 'none';
  drawer.setAttribute('aria-hidden', 'true');
}

function renderAlerts(alerts) {
  const host = document.getElementById('alerts-list');
  if (!alerts.length) {
    host.innerHTML = `
      <div class="tbl-empty">
        <div class="tbl-empty-title">No alerts dispatched yet</div>
        <div class="tbl-empty-sub">Critical and high-risk events will be sent through enabled channels (email, Telegram, etc.).</div>
      </div>`;
    return;
  }
  host.innerHTML = alerts.map((a) => {
    const ok = a.success;
    return `
      <div style="display:flex;align-items:flex-start;gap:10px;padding:8px 10px;border-radius:var(--r-sm);border:1px solid var(--c-border);background:${ok ? 'var(--c-surface-2)' : 'var(--c-high-dim)'}">
        <div style="width:6px;height:6px;border-radius:50%;margin-top:5px;flex-shrink:0;background:${ok ? 'var(--c-low)' : 'var(--c-high)'}" aria-hidden="true"></div>
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:2px">
            <span style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:${ok ? 'var(--c-low)' : 'var(--c-high)'}">${escapeHtml(a.channel)}</span>
            <span style="font-size:11px;color:var(--c-text-4)">${fmt.relTime(a.created_at)}</span>
          </div>
          <div style="font-size:11.5px;color:var(--c-text-3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(a.message || '')}</div>
        </div>
      </div>
    `;
  }).join('');
}

// Bug #4 fix: track whether SSE has pushed any rows so the 2.5s poll
// doesn't wipe live rows with a stale "Waiting…" empty state.
let _ssePacketCount = 0;

function renderPackets(packets) {
  const tbody = document.getElementById('packets-tbody');
  const count = document.getElementById('packets-count');
  if (count) count.textContent = `${packets.length.toLocaleString()} packet${packets.length === 1 ? '' : 's'}`;
  // Bug #4: only show the empty state if SSE hasn't pushed any rows yet
  if (!packets.length && _ssePacketCount === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="tbl-empty"><div class="tbl-empty-title">Waiting for packets…</div><div class="tbl-empty-sub">The live feed will populate as soon as the engine captures traffic.</div></td></tr>';
    return;
  }
  // If SSE rows are visible but API returned empty, don't clear them.
  if (!packets.length) return;
  tbody.innerHTML = packets.slice(0, 30).map((p) => `<tr>${renderPacketCells(p)}</tr>`).join('');
}

// Bug #5 fix: return only <td> cells, NOT a full <tr>, so callers
// can set innerHTML of a <tr> element without nesting issues.
function renderPacketCells(p) {
  return `
    <td style="color:var(--c-text-4);white-space:nowrap">${fmt.shortTime(p.timestamp)}</td>
    <td style="color:var(--c-accent-text)">${escapeHtml(p.source_ip)}:${p.source_port}</td>
    <td style="color:var(--c-text-2)">${escapeHtml(p.destination_ip)}:${p.destination_port}</td>
    <td style="color:var(--c-text-3)">${escapeHtml(p.protocol)}</td>
    <td style="color:var(--c-medium)">${escapeHtml(p.flags || '')}</td>
    <td style="color:var(--c-text-4)">${p.length || 0}</td>
  `;
}

// Kept for any call-sites; now delegates to renderPacketCells.
function renderPacketRow(p) { return renderPacketCells(p); }

function renderEnginePill() {
  const start = document.getElementById('btn-start');
  const stop  = document.getElementById('btn-stop');
  if (!start || !stop) return;

  // Update both dots (header has one visible pill)
  ['engine-dot', 'engine-dot-2'].forEach((dotId) => {
    const dot = document.getElementById(dotId);
    if (!dot) return;
    dot.classList.remove('live', 'sim', 'stopped');
    dot.classList.add(state.running ? (state.actualMode === 'live' ? 'live' : 'sim') : 'stopped');
  });
  ['engine-label', 'engine-label-2'].forEach((lblId) => {
    const lbl = document.getElementById(lblId);
    if (!lbl) return;
    lbl.textContent = state.running
      ? (state.actualMode === 'live' ? 'live' : 'sim')
      : 'stopped';
    lbl.style.color = state.running ? 'var(--c-accent-text)' : 'var(--c-text-4)';
  });

  if (state.running) {
    start.classList.remove('btn-success'); start.classList.add('btn-ghost'); start.disabled = true;
    stop.classList.remove('btn-ghost');   stop.classList.add('btn-danger');  stop.disabled = false;
  } else {
    start.classList.add('btn-success');   start.classList.remove('btn-ghost'); start.disabled = false;
    stop.classList.remove('btn-danger'); stop.classList.add('btn-ghost');     stop.disabled = true;
  }

  const pktEl = document.getElementById('packet-count');
  if (pktEl) pktEl.textContent = state.packetCount.toLocaleString();
  const atkEl = document.getElementById('attack-count');
  if (atkEl) atkEl.textContent = state.attackCount.toLocaleString();
}

function renderChannels(settings, channels) {
  const host = document.getElementById('channel-list');
  // Prefer the rich `alert_channels` payload from /api/status when available;
  // fall back to the legacy boolean-only fields if a downstream proxy stripped
  // the new key.
  const chRow = (label, ready, reason) => `
    <li style="display:flex;align-items:flex-start;gap:8px;padding:5px 0;border-bottom:1px solid var(--c-border)">
      <span style="width:16px;height:16px;border-radius:50%;flex-shrink:0;margin-top:1px;background:${ready ? 'var(--c-low)' : 'var(--c-border-hi)'}" aria-hidden="true"></span>
      <div style="flex:1;min-width:0">
        <div style="font-size:12px;color:${ready ? 'var(--c-text-1)' : 'var(--c-text-4)'}">${escapeHtml(label)}</div>
        ${reason ? `<div style="font-size:11px;color:var(--c-medium);margin-top:1px">${escapeHtml(reason)}</div>` : ''}
      </div>
    </li>`;

  if (Array.isArray(channels) && channels.length) {
    host.innerHTML = channels.map((ch) => chRow(ch.name, !!ch.ready, ch.reason || '')).join('');
    return;
  }
  host.innerHTML = [
    chRow('In-app feed', true, ''),
    chRow('Desktop notifications', !!settings.desktop_alerts, ''),
    chRow('Email (SMTP)', !!settings.email_enabled, ''),
    chRow('Telegram', !!settings.telegram_enabled, ''),
  ].join('');
}

// ---------------------------------------------------------------------------
// IPS rendering
// ---------------------------------------------------------------------------
function renderIPSStatus(ipsStatus) {
  const badge = document.getElementById('ips-status-badge');
  const toggle = document.getElementById('ips-enabled-toggle');
  const inlineToggle = document.getElementById('ips-enabled-toggle-inline');
  const modeSelect = document.getElementById('ips-mode-select');
  const timeoutInput = document.getElementById('ips-timeout-input');
  const expiryInput = document.getElementById('ips-expiry-input');

  if (!ipsStatus) {
    if (badge) { badge.textContent = 'Disabled'; badge.className = 'badge badge-ips-off'; }
    return;
  }

  if (badge) {
    if (ipsStatus.enabled) {
      badge.textContent = `Active · ${ipsStatus.mode}`;
      badge.className = 'badge badge-ips-on';
    } else {
      badge.textContent = 'Disabled';
      badge.className = 'badge badge-ips-off';
    }
  }

  if (toggle) toggle.checked = !!ipsStatus.enabled;
  if (inlineToggle) inlineToggle.checked = !!ipsStatus.enabled;
  if (modeSelect) modeSelect.value = ipsStatus.mode || 'approve';
  if (timeoutInput) timeoutInput.value = ipsStatus.approval_timeout || 60;
  if (expiryInput) expiryInput.value = ipsStatus.block_expiry || 0;

  // Firewall enforcement banner
  const banner = document.getElementById('firewall-enforcement-banner');
  if (!banner) return;
  const fw = ipsStatus.firewall;
  if (!fw) { banner.style.display = 'none'; return; }

  const canEnforce = fw.enforcement_available;
  const fp = fw.windows_unprivileged;
  const fwRunning = fw.windows_firewall_running;

  if (canEnforce) {
    banner.style.display = 'none';
    return;
  }

  const parts = [];
  if (fp === true) parts.push('Run SentinelScan as <strong>Administrator</strong>');
  if (fwRunning === false) parts.push('Turn on <strong>Windows Firewall</strong> (MpsSvc)');
  if (fwRunning === null) parts.push('Windows Firewall status unknown');
  if (parts.length === 0) parts.push('Run as Administrator and turn on Windows Firewall');

  banner.style.display = 'block';
  banner.style.background = 'var(--c-critical-bg, rgba(255,68,68,0.12))';
  banner.style.border = '1px solid var(--c-critical, #f44)';
  banner.style.color = 'var(--c-critical, #f44)';
  banner.innerHTML = `
    <strong>⚠ OS Firewall enforcement unavailable</strong><br>
    Blocked IPs are saved but <strong>NOT enforced</strong> at the network level.
    ${parts.join(' and ')}.
    <br><small>This banner applies to OS-level blocking. The SentinelScan web interface
    (port 5000) is still protected by application-layer filtering.</small>
  `;
}

function renderIPSPending(actions) {
  const list = document.getElementById('ips-pending-list');
  const empty = document.getElementById('ips-empty');

  if (!actions || !actions.length) {
    list.innerHTML = '';
    empty.style.display = 'block';
    return;
  }

  empty.style.display = 'none';
  const riskVar = (lvl) => lvl === 'critical' ? 'var(--c-critical)' : lvl === 'high' ? 'var(--c-high)' : 'var(--c-medium)';
  list.innerHTML = actions.map((a) => {
    const rc = riskVar(a.risk_level);
    const timeLeft = Math.max(0, Math.floor((new Date(a.expires_at) - Date.now()) / 1000));
    const countdownCls = timeLeft < 15 ? 'countdown urgent' : 'countdown';
    const dest = a.destination_ip ? ` → ${escapeHtml(a.destination_ip)}` : '';
    const ports = a.ports && a.ports.length
      ? `<span>${a.ports.length} port${a.ports.length === 1 ? '' : 's'}</span>`
      : '';
    return `
      <div class="ips-pending-item">
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:5px">
            <span style="font-family:'JetBrains Mono',monospace;font-size:12.5px;font-weight:600;color:var(--c-accent-text)">${escapeHtml(a.source_ip)}${dest}</span>
            <span style="font-size:12px;color:${rc};font-weight:500">${escapeHtml(a.threat_type)}</span>
          </div>
          <div class="ips-pending-meta">
            <span>Risk: <strong style="color:${rc}">${a.risk_score.toFixed(1)}/10</strong></span>
            <span>Confidence: <strong>${a.confidence.toFixed(0)}%</strong></span>
            ${ports}
            <span>Expires: <span class="${countdownCls}" data-countdown="${escapeHtml(a.expires_at)}">${timeLeft}s</span></span>
          </div>
        </div>
        <div style="display:flex;gap:6px;flex-shrink:0">
          <button onclick="ipsApprove('${a.id}')" class="btn btn-sm btn-success" title="Allow + temporary whitelist">Allow</button>
          <button onclick="ipsDeny('${a.id}')" class="btn btn-sm btn-danger" title="Block via firewall">Block</button>
        </div>
      </div>
    `;
  }).join('');
}

function tickCountdowns() {
  document.querySelectorAll('[data-countdown]').forEach((el) => {
    const t = new Date(el.dataset.countdown).getTime();
    const left = Math.max(0, Math.floor((t - Date.now()) / 1000));
    el.textContent = `${left}s`;
    el.classList.toggle('urgent', left < 15);
  });
}

function renderApprovedIPs(entries) {
  const tbody = document.getElementById('approved-tbody');
  const table = document.getElementById('approved-table');
  const empty = document.getElementById('approved-empty');

  if (!entries || !entries.length) {
    tbody.innerHTML = '';
    table.style.display = 'none';
    empty.style.display = 'block';
    return;
  }

  empty.style.display = 'none';
  table.style.display = '';
  tbody.innerHTML = entries.map((e) => {
    const expires = new Date(e.expires_at);
    const ttl = Math.max(0, Math.floor((expires - Date.now()) / 1000));
    const expiresStr = `${expires.toLocaleString()} (${ttl}s remaining)`;
    return `
      <tr>
        <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--c-text-1)">${escapeHtml(e.ip)}</td>
        <td style="color:var(--c-text-3);font-size:12px">${escapeHtml(e.reason || '—')}</td>
        <td style="color:var(--c-text-3);font-size:12px">${escapeHtml(e.added_by)}</td>
        <td style="color:var(--c-text-3);font-size:11.5px">${expiresStr}</td>
        <td>
          <button type="button" data-approved-block="${escapeHtml(e.ip)}" class="btn btn-sm btn-danger">
            Block
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function renderBlockedIPs(blocked) {
  const tbody = document.getElementById('blocked-tbody');
  const table = document.getElementById('blocked-table');
  const empty = document.getElementById('blocked-empty');

  if (!blocked || !blocked.length) {
    tbody.innerHTML = '';
    table.style.display = 'none';
    empty.style.display = 'block';
    return;
  }

  empty.style.display = 'none';
  table.style.display = '';
  // Status mapping is exhaustive — never silently default to Pending.
  // An unknown status means the API/DB contract is out of sync, which
  // is a loud failure: surface it as "Unknown" with a red ring so the
  // operator investigates instead of treating it as healthy.
  const KNOWN_STATUSES = new Set(['verified', 'failed', 'applied', 'pending']);
  const statusBadge = (s) => {
    if (s === 'verified') return '<span class="badge badge-success">VERIFIED</span>';
    if (s === 'failed')   return '<span class="badge badge-danger">FAILED</span>';
    if (s === 'applied')  return '<span class="badge badge-warn">APPLIED</span>';
    if (s === 'pending')  return '<span class="badge badge-warn">PENDING</span>';
    // Anything else — null, undefined, or a status code we don't
    // recognise — is loud-red. A FAILED row must never look like PENDING.
    console.warn('Blocked IPs: unknown status from API:', s);
    return '<span class="badge badge-danger">UNKNOWN</span>';
  };
  const verifiedAt = (iso) => iso ? escapeHtml(new Date(iso).toLocaleString()) : '—';
  tbody.innerHTML = blocked.map((r) => `
    <tr title="${escapeHtml(r.failure_reason || '')}">
      <td style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--c-text-1)">${escapeHtml(r.ip)}</td>
      <td style="color:var(--c-text-3)">${escapeHtml(r.direction)}</td>
      <td>${statusBadge(r.status)}${r.backend ? ` <span style="color:var(--c-text-4);font-size:11px;margin-left:6px">${escapeHtml(r.backend)}</span>` : ''}</td>
      <td style="color:var(--c-text-3);font-size:11.5px">${verifiedAt(r.verified_at)}</td>
      <td style="color:var(--c-text-3);font-size:12px">${escapeHtml(r.reason || '—')}</td>
      <td>
        <button type="button" data-unblock="${escapeHtml(r.ip)}" class="btn btn-sm btn-danger">
          Unblock
        </button>
      </td>
    </tr>
  `).join('');
}

async function refreshIPS() {
  try {
    const [ipsStatus, pending, fwRules, whitelist] = await Promise.all([
      API.get('/api/ips/status'),
      API.get('/api/ips/pending'),
      API.get('/api/firewall/rules'),
      API.get('/api/ips/whitelist'),
    ]);
    renderIPSStatus(ipsStatus);
    renderIPSPending(pending);
    renderBlockedIPs(fwRules.rules || []);
    renderApprovedIPs(whitelist.entries || []);
  } catch (err) {
    console.error('IPS refresh failed', err);
  }
}

window.ipsApprove = async function(actionId) {
  try {
    // Spec endpoint: POST /api/ips/allow/{id} (Human-in-the-Loop IPS).
    const r = await API.post(`/api/ips/allow/${actionId}`);
    if (r.ok) {
      showToast({
        title: 'IP Allowed',
        body: `Whitelisted for ${r.whitelist_ttl_seconds || 300}s`,
        level: 'success',
        timeout: 3000,
      });
      refreshIPS();
    } else {
      showToast({ title: 'Approval failed', body: r.error || 'Unknown error', level: 'error' });
    }
  } catch (err) {
    showToast({ title: 'Network error', body: String(err), level: 'error' });
  }
};

window.ipsDeny = async function(actionId) {
  const confirmed = confirm('Are you sure you want to BLOCK this IP? This will add a firewall rule.');
  if (!confirmed) return;
  try {
    // Spec endpoint: POST /api/ips/block/{id}
    const r = await API.post(`/api/ips/block/${actionId}`);
    if (r.ok) {
      showToast({
        title: 'IP Blocked',
        body: r.firewall_applied ? 'Firewall rule applied' : 'Recorded only — needs admin for OS firewall',
        level: r.firewall_applied ? 'success' : 'info',
        timeout: 5000,
      });
      await refreshIPS();
      refreshAll();
    } else {
      showToast({ title: 'Block failed', body: r.error || 'Unknown error', level: 'error' });
    }
  } catch (err) {
    showToast({ title: 'Network error', body: String(err), level: 'error' });
  }
};

window.ipsUnblock = async function(ip) {
  if (!ip) return;
  const confirmed = confirm(`Unblock ${ip}?\n\nThis will remove the firewall rule and allow traffic from this IP again.`);
  if (!confirmed) return;
  try {
    const r = await API.post('/api/ips/unblock', { ip });
    if (r.ok) {
      showToast({ title: 'IP Unblocked', body: `${ip} has been unblocked`, level: 'success', timeout: 3000 });
      refreshIPS();
    } else {
      showToast({ title: 'Unblock failed', body: r.error || 'Unknown error', level: 'error' });
    }
  } catch (err) {
    showToast({ title: 'Network error', body: String(err), level: 'error' });
  }
};

window.ipsApprovedBlock = async function(ip) {
  if (!ip) return;
  const confirmed = confirm(`Block approved IP ${ip}?\n\nThis will remove it from the whitelist and add a firewall rule to block traffic.`);
  if (!confirmed) return;
  try {
    const r = await API.post(`/api/ips/whitelist/${ip}/block`);
    if (r.ok) {
      showToast({
        title: r.firewall_applied ? 'IP Blocked' : 'IP Blocked (NOT enforced)',
        body: r.firewall_applied
          ? 'Removed from whitelist and blocked via OS firewall'
          : 'Removed from whitelist but OS firewall rule NOT applied. Check the banner above for instructions.',
        level: r.firewall_applied ? 'success' : 'error',
        timeout: 8000,
      });
      await refreshIPS();
      refreshAll();
    } else {
      showToast({ title: 'Block failed', body: r.error || 'Unknown error', level: 'error' });
    }
  } catch (err) {
    showToast({ title: 'Network error', body: String(err), level: 'error' });
  }
};

async function refreshIPS() {
  try {
    const [ipsStatus, pending, blocked, whitelist] = await Promise.all([
      API.get('/api/ips/status'),
      API.get('/api/ips/pending'),
      API.get('/api/ips/blocked'),
      API.get('/api/ips/whitelist'),
    ]);
    renderIPSStatus(ipsStatus);
    renderIPSPending(pending);
    // /api/ips/blocked now returns {ok, backend, count, rules:[...]}
    // (matches /api/firewall/rules). Accept both shapes for safety.
    const rules = Array.isArray(blocked) ? blocked : (blocked.rules || []);
    renderBlockedIPs(rules);
    renderApprovedIPs(whitelist.entries || []);
  } catch (err) {
    console.error('IPS refresh failed', err);
  }
}

// ---------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------
function showToast({ title, body, level = 'info', timeout = 4500 }) {
  const host = document.getElementById('toast-host');
  if (!host) {
    console.log(`[toast:${level}]`, title, body);
    return;
  }
  const node = document.createElement('div');
  const levelClass = ['success', 'error', 'info', 'high', 'critical'].includes(level) ? level : 'info';
  node.className = `toast ${levelClass}`;
  const safeTitle = escapeHtml(title || '');
  const safeMsg   = body ? `<div class="toast-msg">${escapeHtml(body)}</div>` : '';
  node.innerHTML = `
    <svg class="toast-icon" width="16" height="16"><use href="#icon-info"/></svg>
    <div class="toast-body">
      <div class="toast-title">${safeTitle}</div>
      ${safeMsg}
    </div>
    <button style="position:absolute;top:10px;right:10px;color:var(--c-text-4);line-height:1;background:none;border:none;cursor:pointer;font-size:13px" aria-label="Dismiss" onclick="this.parentElement.remove()">&#x2715;</button>
  `;
  host.appendChild(node);
  setTimeout(() => {
    node.style.opacity = '0';
    node.style.transition = 'opacity .4s';
  }, timeout);
  setTimeout(() => node.remove(), timeout + 400);
}

function showAttackToast(attack) {
  showToast({
    title: `${attack.risk_level.toUpperCase()} — ${attack.scan_type}`,
    body:
      `From ${attack.source?.ip}  ·  tool: ${attack.source?.tool_guess || 'Unknown'}  ·  ` +
      `${attack.unique_ports} ports  ·  score ${attack.risk_score.toFixed(1)}/10`,
    level: attack.risk_level === 'critical' ? 'error'
         : attack.risk_level === 'high'    ? 'error'
         : 'info',
    timeout: 5500,
  });
}

// ---------------------------------------------------------------------------
// Data fetch + polling
// ---------------------------------------------------------------------------
async function refreshAll() {
  if (state.isRefreshing) return;
  state.isRefreshing = true;
  setLastUpdated(true);
  try {
    const [status, stats, attacks, alerts, packets, ipsStatus, pending, blocked, whitelist] = await Promise.all([
      API.get('/api/status'),
      API.get('/api/stats'),
      API.get(`/api/attacks?limit=${state.pagination.limit}&offset=0`),
      API.get('/api/alerts?limit=30'),
      API.get('/api/packets?limit=40'),
      API.get('/api/ips/status'),
      API.get('/api/ips/pending'),
      API.get('/api/ips/blocked'),
      API.get('/api/ips/whitelist'),
    ]);
    if (!status || !stats) return;

    state.running = status.summary.running;
    state.actualMode = status.summary.mode;
    state.packetCount = status.summary.packet_count;
    state.attackCount = status.summary.attack_count;

    renderEnginePill();
    renderChannels(status.settings, status.alert_channels);
    renderStatCards(stats);
    updateCharts(stats);
    renderTopSources(stats.top_sources);

    state.pagination.offset = 0;
    state.pagination.hasMore = (attacks && attacks.length === state.pagination.limit);
    state.pagination.isLoadingMore = false;
    state.allAttacks = attacks || [];
    renderAttacks();

    renderAlerts(alerts || []);
    renderPackets(packets || []);
    renderIPSStatus(ipsStatus);
    renderIPSPending(pending);
    // /api/ips/blocked returns {rules:[...]} (DB-backed) — accept both shapes.
    const blockedRules = Array.isArray(blocked) ? blocked : (blocked.rules || []);
    renderBlockedIPs(blockedRules);
    renderApprovedIPs(whitelist.entries || []);
    state.firstLoadDone = true;
    state.lastFetchAt = Date.now();
  } catch (err) {
    console.error('refresh failed', err);
  } finally {
    state.isRefreshing = false;
    setLastUpdated(false, state.lastFetchAt);
  }
}

// SSE real-time event stream — replaces fast packet polling.
let _sseSource = null;

function connectSSE() {
  if (_sseSource) { _sseSource.close(); _sseSource = null; }
  try {
    const es = new EventSource('/api/events/stream');
    es.addEventListener('attack', (e) => {
      try {
        const attack = JSON.parse(e.data);
        if (attack && attack.id) {
          state.lastSSEAttack = attack;
          // Trigger a full refresh immediately on new attack.
          if (!state.isRefreshing) refreshAll();
        }
      } catch { /* ignore parse errors */ }
    });
    es.addEventListener('packet', (e) => {
      try {
        const pkt = JSON.parse(e.data);
        if (pkt && pkt.timestamp) {
          _ssePacketCount++;  // Bug #4: mark that SSE has delivered at least one packet
          const tbody = document.getElementById('packets-tbody');
          if (tbody) {
            // Bug #5 fix: renderPacketCells returns <td> elements.
            // Insert it via insertAdjacentHTML into a created TR.
            tbody.insertAdjacentHTML('afterbegin', `<tr>${renderPacketCells(pkt)}</tr>`);
            while (tbody.children.length > 100) {
              tbody.removeChild(tbody.lastChild);
            }
          }
          // Bump the running packet count.
          const el = document.getElementById('packet-count');
          if (el) {
            const curr = parseInt(el.textContent.replace(/,/g, ''), 10) || 0;
            el.textContent = (curr + 1).toLocaleString();
          }
        }
      } catch { /* ignore parse errors */ }
    });
    es.addEventListener('heartbeat', () => { /* keep-alive, no action */ });
    es.onerror = () => {
      // Reconnect on error (browser EventSource does this automatically,
      // but we log for debugging).
      console.debug('SSE reconnecting…');
    };
    _sseSource = es;
  } catch (err) {
    console.warn('SSE not available, falling back to polling', err);
  }
}

function startPolling() {
  stopPolling();
  state.pollingHandle = setInterval(refreshAll, 2500);
  connectSSE();
  refreshAll();
  if (!state._countdownHandle) {
    state._countdownHandle = setInterval(tickCountdowns, 1000);
  }
}
function stopPolling() {
  if (state.pollingHandle) clearInterval(state.pollingHandle);
  state.pollingHandle = null;
  if (_sseSource) { _sseSource.close(); _sseSource = null; }
}

// ---------------------------------------------------------------------------
// Control wiring
// ---------------------------------------------------------------------------
async function startEngine(mode) {
  const btn = document.getElementById('btn-start');
  if (btn.disabled) return;
  // Just disable the button — relying on btn:disabled CSS (opacity 0.40,
  // pointer-events: none) for visual feedback. We deliberately do NOT
  // touch btn.textContent because the buttons contain SVG icons and
  // textContent assignment would strip the icon and leave plain text.
  btn.disabled = true;
  let succeeded = false;
  try {
    const r = await API.post('/api/engine/start', { mode });
    if (r.ok) {
      succeeded = true;
      // Optimistic UI update — flip the button immediately so the user
      // doesn't see a stale "▶ Start" while refreshAll() round-trips.
      state.running = true;
      state.actualMode = r.mode;
      renderEnginePill();
      showToast({
        title: r.already_running ? 'Engine already running' : 'Engine started',
        body: `Mode: ${r.mode}`,
        level: 'success',
      });
      refreshAll();
    } else {
      showToast({
        title: 'Engine failed to start',
        body: r.hint ? `${r.error}\n\n${r.hint}` : (r.error || 'Unknown error'),
        level: 'error',
        timeout: 8000,
      });
    }
  } catch (err) {
    console.error('startEngine failed', err);
    showToast({ title: 'Network error', body: String(err), level: 'error' });
  } finally {
    // Only re-enable on FAILURE. On success renderEnginePill left the
    // button disabled because the engine is running.
    if (!succeeded) {
      btn.disabled = false;
    }
  }
}

async function stopEngine() {
  const btn = document.getElementById('btn-stop');
  if (btn.disabled) return;
  btn.disabled = true;
  let succeeded = false;
  try {
    const r = await API.post('/api/engine/stop');
    if (r.ok) {
      succeeded = true;
      // Optimistic UI update — flip back to Start immediately.
      state.running = false;
      state.actualMode = null;
      renderEnginePill();
      showToast({
        title: 'Engine stopped',
        body: `Packets: ${r.summary?.packet_count ?? 0}, attacks: ${r.summary?.attack_count ?? 0}`,
        level: 'info',
      });
      refreshAll();
    } else {
      showToast({
        title: 'Stop failed',
        body: r.error || 'Unknown error',
        level: 'error',
      });
    }
  } catch (err) {
    console.error('stopEngine failed', err);
    showToast({ title: 'Network error', body: String(err), level: 'error' });
  } finally {
    // Only re-enable on FAILURE. On success renderEnginePill re-enabled
    // the button because the engine is stopped.
    if (!succeeded) {
      btn.disabled = false;
    }
  }
}

async function injectPacket() {
  const btn = document.getElementById('btn-inject');
  if (btn.disabled) return;
  // Disable-only — the button has an SVG icon and setting textContent would
  // strip it.  Visual feedback comes from btn:disabled CSS.
  btn.disabled = true;
  try {
    const payloads = [
      { source_ip: '192.168.1.66', protocol: 'TCP', flags: { SYN: true }, destination_port: 22 },
      { source_ip: '203.0.113.50', protocol: 'ICMP', destination_port: 0 },
      { source_ip: '185.220.101.42', protocol: 'TCP', flags: { FIN: true, PSH: true, URG: true }, destination_port: 80 },
      { source_ip: '91.214.78.4', protocol: 'TCP', flags: { FIN: true, PSH: true, URG: true }, destination_port: 443 },
      { source_ip: '45.227.253.109', protocol: 'TCP', flags: {}, destination_port: 21 },
    ];
    const p = payloads[Math.floor(Math.random() * payloads.length)];
    const r = await API.post('/api/engine/inject', p);
    if (r.ok) {
      showToast({
        title: 'Packet injected',
        body: `${p.protocol} ${p.source_ip} → :${p.destination_port}`,
        level: 'success',
        timeout: 2500,
      });
    } else {
      showToast({ title: 'Inject failed', body: r.error || 'Unknown error', level: 'error' });
    }
  } catch (err) {
    console.error('inject failed', err);
    showToast({ title: 'Network error', body: String(err), level: 'error' });
  } finally {
    btn.disabled = false;
  }
}

function initControls() {
  const $ = (id) => document.getElementById(id);
  const safe = (id, fn) => {
    const el = $(id);
    if (!el) {
      console.warn(`[sentinelscan] element #${id} not found; skipping listener`);
      return;
    }
    el.addEventListener('click', fn);
  };

  safe('btn-start', () => {
    const checked = document.querySelector('input[name="mode"]:checked');
    const mode = checked ? checked.value : 'auto';
    startEngine(mode);
  });
  safe('btn-stop', stopEngine);
  safe('btn-refresh', () => {
    refreshAll();
    showToast({ title: 'Refreshed', body: 'Dashboard data reloaded', level: 'info', timeout: 1500 });
  });
  safe('btn-inject', injectPacket);
  safe('btn-theme', () => {
    applyTheme(THEME.current === 'light' ? 'dark' : 'light');
    showToast({
      title: `Theme: ${THEME.current}`,
      body: THEME.current === 'light' ? 'Switched to light mode' : 'Switched to dark mode',
      level: 'info',
      timeout: 1200,
    });
  });
  safe('btn-logout', async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
    } catch (e) { /* ignore */ }
    location.replace('/login');
  });

  // Mode radios — visual feedback
  document.querySelectorAll('input[name="mode"]').forEach((r) => {
    r.addEventListener('change', (e) => {
      document.querySelectorAll('.mode-option').forEach((opt) => opt.classList.remove('selected'));
      const label = e.target.closest('label');
      if (label) label.classList.add('selected');
      if (e.target.checked) {
        showToast({
          title: `Mode: ${e.target.value}`,
          body: e.target.value === 'live'
            ? 'Requires Npcap + admin. Will fall back to sim if unavailable.'
            : e.target.value === 'auto'
              ? 'Live capture with automatic simulation fallback.'
              : 'Simulation only — no raw packet capture.',
          level: 'info',
          timeout: 2500,
        });
      }
    });
  });

  // Intensity slider — large visible value
  const intensity = $('intensity');
  if (intensity) {
    const indicator = document.getElementById('intensity-indicator');
    const update = debounce(async (v) => {
      try {
        await API.post('/api/engine/intensity', { value: v });
      } catch (err) {
        console.error('intensity update failed', err);
      }
    }, 150);
    intensity.addEventListener('input', () => {
      const v = parseFloat(intensity.value);
      if (indicator) indicator.textContent = `${v.toFixed(1)}×`;
      update(v);
    });
  }

  const pdf = $('dl-pdf');
  if (pdf) pdf.addEventListener('click', () => {
    showToast({ title: 'Generating PDF report…', body: 'This can take a moment on a busy database.', level: 'info', timeout: 3000 });
  });
  const csv = $('dl-csv');
  if (csv) csv.addEventListener('click', () => {
    showToast({ title: 'Generating CSV…', body: 'Download will start in a moment.', level: 'info', timeout: 2500 });
  });

  safe('btn-ips-refresh', () => {
    refreshIPS();
    showToast({ title: 'IPS Refreshed', body: 'Pending actions and blocked IPs updated', level: 'info', timeout: 1500 });
  });

  safe('btn-block-ip', async () => {
    const ip = prompt('Enter IP address to block:');
    if (!ip) return;
    // Bug #6 fix: accept both IPv4 (with octet validation) and IPv6.
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$|^::1$|^::$/;
    const isIPv4 = ipv4Regex.test(ip) && ip.split('.').every((o) => Number(o) <= 255);
    const isIPv6 = ipv6Regex.test(ip);
    if (!isIPv4 && !isIPv6) {
      showToast({ title: 'Invalid IP', body: `"${ip}" is not a valid IPv4 or IPv6 address`, level: 'error' });
      return;
    }
    try {
      const r = await API.post('/api/ips/block', { ip, reason: 'Manual block via dashboard' });
      if (r.ok) {
        showToast({ title: 'IP Blocked', body: `${ip} has been blocked`, level: 'success', timeout: 3000 });
        refreshIPS();
      } else {
        showToast({ title: 'Block failed', body: r.error || 'Unknown error', level: 'error' });
      }
    } catch (err) {
      showToast({ title: 'Network error', body: String(err), level: 'error' });
    }
  });

  safe('btn-ips-save', async () => {
    const toggle = document.getElementById('ips-enabled-toggle');
    const modeSelect = document.getElementById('ips-mode-select');
    const timeoutInput = document.getElementById('ips-timeout-input');
    const expiryInput = document.getElementById('ips-expiry-input');
    const status = document.getElementById('ips-save-status');

    const settings = {
      enabled: toggle ? toggle.checked : false,
      mode: modeSelect ? modeSelect.value : 'approve',
      approval_timeout: timeoutInput ? parseInt(timeoutInput.value) || 60 : 60,
      block_expiry: expiryInput ? parseInt(expiryInput.value) || 0 : 0,
    };

    if (status) status.textContent = 'Saving…';
    try {
      const r = await API.post('/api/ips/settings', settings);
      if (r.ok) {
        if (status) status.textContent = '✓ Saved';
        showToast({ title: 'IPS Settings Saved', body: 'Configuration updated', level: 'success', timeout: 3000 });
        refreshIPS();
        setTimeout(() => { if (status) status.textContent = ''; }, 3000);
      } else {
        if (status) status.textContent = '';
        showToast({ title: 'Save failed', body: r.error || 'Unknown error', level: 'error' });
      }
    } catch (err) {
      if (status) status.textContent = '';
      showToast({ title: 'Network error', body: String(err), level: 'error' });
    }
  });

  // Bug #3 fix: both IPS toggles are now symmetric — each mirrors the
  // other AND auto-triggers a save so the state is never left dirty.
  const inlineToggle = document.getElementById('ips-enabled-toggle-inline');
  if (inlineToggle) {
    inlineToggle.addEventListener('change', () => {
      const otherToggle = document.getElementById('ips-enabled-toggle');
      if (otherToggle) otherToggle.checked = inlineToggle.checked;
      document.getElementById('btn-ips-save')?.click();  // auto-save
    });
  }
  const settingsToggle = document.getElementById('ips-enabled-toggle');
  if (settingsToggle) {
    settingsToggle.addEventListener('change', () => {
      const inline = document.getElementById('ips-enabled-toggle-inline');
      if (inline) inline.checked = settingsToggle.checked;
      document.getElementById('btn-ips-save')?.click();  // Bug #3: also auto-save
    });
  }

  // Attack search & filter
  // Bug #11 fix: debounce the search so we don't do a full innerHTML
  // replacement (+ scroll-top reset + observer reconnect) on every keystroke.
  const search = document.getElementById('attack-search');
  if (search) {
    const debouncedRender = debounce(() => {
      state.filters.search = search.value;
      renderAttacks();
    }, 120);
    search.addEventListener('input', debouncedRender);
  }
  document.querySelectorAll('.filter-chip[data-risk]').forEach((chip) => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('.filter-chip[data-risk]').forEach((c) => c.classList.remove('active'));
      chip.classList.add('active');
      state.filters.risk = chip.dataset.risk;
      renderAttacks();
    });
  });

  // Attack card click → open drawer.  Cards live in #events-list (the
  // redesigned vertical card list).  Keyboard nav (j/k/Enter) lives in
  // the global keydown handler below.
  const eventsList = document.getElementById('events-list');
  if (eventsList) {
    eventsList.addEventListener('click', (e) => {
      const card = e.target.closest('li[data-attack-id]');
      if (!card) return;
      // Selection follows the click so keyboard nav and click nav agree.
      const idx = Number(card.dataset.eventIndex);
      if (Number.isFinite(idx)) {
        state.selectedEventIdx = idx;
        renderAttacks();
      }
      openAttackDrawer(card.dataset.attackId);
    });
  }

  // Blocked IPs: ONLY the unblock button triggers unblock — clicking
  // the row, IP, or any other cell does nothing.
  const blockedTbody = document.getElementById('blocked-tbody');
  if (blockedTbody) {
    blockedTbody.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-unblock]');
      if (!btn) return;
      e.stopPropagation();
      ipsUnblock(btn.dataset.unblock);
    });
  }

  // Approved IPs: Block button removes from whitelist + adds to firewall.
  const approvedTbody = document.getElementById('approved-tbody');
  if (approvedTbody) {
    approvedTbody.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-approved-block]');
      if (!btn) return;
      e.stopPropagation();
      ipsApprovedBlock(btn.dataset.approvedBlock);
    });
  }

  // Drawer close
  document.querySelectorAll('[data-drawer-close]').forEach((el) => {
    el.addEventListener('click', closeDrawer);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeDrawer();
  });

  // Sidebar nav: highlight current section as user scrolls
  const navLinks = new Map();
  document.querySelectorAll('.sidebar a').forEach((a) => {
    const hash = a.getAttribute('href') || '';
    if (hash.startsWith('#')) navLinks.set(hash.slice(1), a);
  });

  if ('IntersectionObserver' in window) {
    const obs = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          document.querySelectorAll('.sidebar a').forEach((a) => a.classList.remove('active'));
          const link = navLinks.get(entry.target.id);
          if (link) link.classList.add('active');
        }
      });
    }, { rootMargin: '-30% 0px -60% 0px' });
    document.querySelectorAll('.page-section').forEach((el) => obs.observe(el));
  }

  // Keyboard shortcuts:
  //   R            → refresh
  //   J / ArrowDown → move selection down in the event list
  //   K / ArrowUp   → move selection up
  //   Enter         → open the selected event's drawer
  document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === 'r' || e.key === 'R') {
      refreshAll();
      showToast({ title: 'Refreshed', body: 'Dashboard data reloaded', level: 'info', timeout: 1200 });
      return;
    }
    const filtered = getFilteredAttacks();
    if (!filtered.length) return;
    const cap = filtered.length;
    if (e.key === 'j' || e.key === 'J' || e.key === 'ArrowDown') {
      e.preventDefault();
      state.selectedEventIdx = Math.min(cap - 1, (state.selectedEventIdx || 0) + 1);
      renderAttacks();
      scrollSelectedIntoView();
    } else if (e.key === 'k' || e.key === 'K' || e.key === 'ArrowUp') {
      e.preventDefault();
      state.selectedEventIdx = Math.max(0, (state.selectedEventIdx || 0) - 1);
      renderAttacks();
      scrollSelectedIntoView();
    } else if (e.key === 'Enter') {
      const idx = state.selectedEventIdx || 0;
      const id = filtered[idx] && filtered[idx].id;
      if (id != null) {
        e.preventDefault();
        openAttackDrawer(id);
      }
    }
  });
}

function scrollSelectedIntoView() {
  const el = document.querySelector('#events-list li.is-selected');
  if (el && typeof el.scrollIntoView === 'function') {
    el.scrollIntoView({ block: 'nearest' });
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
function boot() {
  console.log(
    '%cSentinelScan AI %cdashboard initialized',
    'color:#22D3EE;font-weight:bold;font-size:13px',
    'color:#94A3B8'
  );

  try { initCharts(); } catch (e) { console.error('initCharts failed', e); }
  try { initControls(); } catch (e) { console.error('initControls failed', e); }
  try { initInfiniteScroll(); } catch (e) { console.error('initInfiniteScroll failed', e); }
  try { startPolling(); } catch (e) { console.error('startPolling failed', e); }
}

window.addEventListener('error', (e) => {
  console.error('[sentinelscan] uncaught', e.error || e.message);
  try {
    showToast({
      title: 'Dashboard error',
      body: (e.error && e.error.message) || e.message || 'Unknown error',
      level: 'error',
      timeout: 8000,
    });
  } catch { /* */ }
});
window.addEventListener('unhandledrejection', (e) => {
  console.error('[sentinelscan] unhandled rejection', e.reason);
  try {
    showToast({
      title: 'Dashboard error',
      body: String(e.reason && e.reason.message || e.reason || 'Unknown'),
      level: 'error',
      timeout: 8000,
    });
  } catch { /* */ }
});

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}

// ===========================================================================
// Phase 3: Scheduled Reports, Per-Source Timeline, Network Topology
// ===========================================================================

// ---- Scheduled Reports panel ---------------------------------------------
async function loadSchedules() {
  const list = await API.get('/api/reports/schedules');
  const tbody = document.getElementById('schedules-tbody');
  const table = document.getElementById('schedules-table');
  const empty = document.getElementById('schedules-empty');
  if (!tbody) return;
  if (!list || !list.length) {
    if (table) table.style.display = 'none';
    if (empty) empty.style.display = 'block';
    tbody.innerHTML = '';
    return;
  }
  if (table) table.style.display = 'table';
  if (empty) empty.style.display = 'none';
  tbody.innerHTML = list.map((sc) => `
    <tr data-schedule-id="${sc.id}">
      <td>${escapeHtml(sc.name)}</td>
      <td>${escapeHtml(sc.frequency)}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--c-text-3);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(sc.recipients || '—')}</td>
      <td style="color:var(--c-text-3);font-size:11.5px">${sc.last_run_at ? fmt.shortTime(sc.last_run_at) : '—'}</td>
      <td style="color:var(--c-text-3);font-size:11.5px">${sc.next_run_at ? fmt.shortTime(sc.next_run_at) : '—'}</td>
      <td>
        <label class="toggle">
          <input type="checkbox" class="sched-active" ${sc.is_active ? 'checked' : ''} aria-label="Active">
          <span class="toggle-track"></span>
          <span class="toggle-thumb"></span>
        </label>
      </td>
      <td style="display:flex;gap:4px">
        <button class="btn btn-sm btn-ghost btn-icon sched-run" data-tip="Run now" aria-label="Run now">
          <svg width="13" height="13"><use href="#icon-play"/></svg>
        </button>
        <button class="btn btn-sm btn-ghost btn-icon sched-edit" data-tip="Edit" aria-label="Edit">
          <svg width="13" height="13"><use href="#icon-settings"/></svg>
        </button>
        <button class="btn btn-sm btn-ghost btn-icon sched-del" data-tip="Delete" aria-label="Delete">
          <svg width="13" height="13"><use href="#icon-x"/></svg>
        </button>
      </td>
    </tr>
  `).join('');
}

function promptSchedule(existing) {
  // ponytail: tiny inline modal — 3 fields is enough for daily/weekly + recipients.
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:80;display:flex;align-items:center;justify-content:center';
  const initial = existing || { name: '', frequency: 'daily', recipients: '' };
  overlay.innerHTML = `
    <div style="background:var(--c-surface-1);border:1px solid var(--c-border);border-radius:var(--r-lg);padding:20px;width:380px;max-width:90vw">
      <div style="font-size:14px;font-weight:600;margin-bottom:14px">${existing ? 'Edit' : 'New'} Schedule</div>
      <div style="display:flex;flex-direction:column;gap:12px">
        <div>
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--c-text-4);margin-bottom:4px">Name</div>
          <input id="sched-name" class="field" type="text" value="${escapeHtml(initial.name)}" placeholder="e.g. Nightly summary" />
        </div>
        <div>
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--c-text-4);margin-bottom:4px">Frequency</div>
          <select id="sched-freq" class="field">
            <option value="daily" ${initial.frequency === 'daily' ? 'selected' : ''}>Daily</option>
            <option value="weekly" ${initial.frequency === 'weekly' ? 'selected' : ''}>Weekly</option>
          </select>
        </div>
        <div>
          <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--c-text-4);margin-bottom:4px">Recipients (comma-separated)</div>
          <input id="sched-recipients" class="field" type="text" value="${escapeHtml(initial.recipients)}" placeholder="sec@example.com, ops@example.com" />
        </div>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
        <button id="sched-cancel" class="btn btn-ghost">Cancel</button>
        <button id="sched-save" class="btn btn-primary">Save</button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);
  return new Promise((resolve) => {
    const close = (val) => { overlay.remove(); resolve(val); };
    overlay.querySelector('#sched-cancel').onclick = () => close(null);
    overlay.querySelector('#sched-save').onclick = () => close({
      name: overlay.querySelector('#sched-name').value.trim(),
      frequency: overlay.querySelector('#sched-freq').value,
      recipients: overlay.querySelector('#sched-recipients').value.trim(),
    });
  });
}

function initSchedules() {
  document.getElementById('btn-sched-new')?.addEventListener('click', async () => {
    const data = await promptSchedule();
    if (!data || !data.name) return;
    const r = await API.post('/api/reports/schedules', data);
    if (r.ok) {
      showToast({ title: 'Schedule created', body: data.name, level: 'success' });
      loadSchedules();
    } else {
      showToast({ title: 'Failed to create schedule', body: r.error || 'Unknown error', level: 'error' });
    }
  });

  document.getElementById('schedules-tbody')?.addEventListener('click', async (e) => {
    const row = e.target.closest('tr[data-schedule-id]');
    if (!row) return;
    const id = parseInt(row.dataset.scheduleId, 10);
    if (e.target.closest('.sched-active')) {
      const isActive = e.target.checked;
      const r = await fetch(`/api/reports/schedules/${id}`, {
        method: 'PATCH', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_active: isActive }),
      }).then((r) => r.json());
      if (r.ok) loadSchedules();
    } else if (e.target.closest('.sched-run')) {
      showToast({ title: 'Running schedule…', body: 'Generating report', level: 'info', timeout: 2000 });
      const r = await API.post(`/api/reports/schedules/${id}/run`, {});
      if (r.ok) {
        showToast({
          title: r.emailed ? 'Report emailed' : 'Report generated',
          body: r.message || `${r.attacks || 0} attacks`,
          level: r.emailed ? 'success' : 'info',
        });
        loadSchedules();
      }
    } else if (e.target.closest('.sched-edit')) {
      const current = Array.from(row.children).map((c) => c.textContent.trim());
      const data = await promptSchedule({
        name: current[0],
        frequency: current[1] === 'weekly' ? 'weekly' : 'daily',
        recipients: current[2] === '—' ? '' : current[2],
      });
      if (!data) return;
      const r = await fetch(`/api/reports/schedules/${id}`, {
        method: 'PATCH', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      }).then((r) => r.json());
      if (r.ok) {
        showToast({ title: 'Schedule updated', level: 'success' });
        loadSchedules();
      }
    } else if (e.target.closest('.sched-del')) {
      if (!confirm('Delete this schedule?')) return;
      const r = await fetch(`/api/reports/schedules/${id}`, {
        method: 'DELETE', credentials: 'include',
      }).then((r) => r.json());
      if (r.ok) {
        showToast({ title: 'Schedule deleted', level: 'info' });
        loadSchedules();
      }
    }
  });
}

// ---- Per-source timeline --------------------------------------------------
let tlChartAttacks = null;
let tlChartPackets = null;

async function loadTimeline() {
  const ip = document.getElementById('tl-ip-input').value.trim();
  if (!ip) {
    showToast({ title: 'IP required', body: 'Enter a source IP first', level: 'error' });
    return;
  }
  const hours = document.getElementById('tl-window-select').value;
  const since = new Date(Date.now() - hours * 3600 * 1000).toISOString();
  const data = await API.get(`/api/sources/${encodeURIComponent(ip)}/timeline?since=${encodeURIComponent(since)}`);
  if (!data || !data.ok) {
    showToast({ title: 'Timeline failed', body: data?.error || 'Unknown error', level: 'error' });
    return;
  }
  renderTimeline(data);
}

function renderTimeline(data) {
  const c = getColors();
  const summary = document.getElementById('tl-summary');
  if (summary) summary.innerHTML = `
    <span><strong style="color:var(--c-text-2)">${escapeHtml(data.ip)}</strong></span>
    <span>${data.attack_count} attack${data.attack_count === 1 ? '' : 's'}</span>
    <span>${data.packet_count} packet${data.packet_count === 1 ? '' : 's'}</span>
  `;

  // Attack scatter: x=time, y=scan_type index, point size = risk
  const scanTypes = Array.from(new Set(data.attacks.map((a) => a.scan_type)));
  const yMap = Object.fromEntries(scanTypes.map((s, i) => [s, i]));
  const attackPoints = data.attacks.map((a) => ({
    x: a.time, y: yMap[a.scan_type] ?? 0,
    r: Math.max(4, (a.risk_score || 0) * 1.6),
    _meta: a,
  }));

  if (tlChartAttacks) tlChartAttacks.destroy();
  const ctx1 = document.getElementById('chart-tl-attacks');
  if (ctx1) {
    tlChartAttacks = new Chart(ctx1, {
      type: 'bubble',
      data: { datasets: [{
        label: 'attacks',
        data: attackPoints,
        backgroundColor: data.attacks.map((a) => c.risk[a.risk_level] || c.accent),
        borderColor: c.border,
      }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: {
          x: { type: 'time', time: { unit: 'minute', displayFormats: { minute: 'HH:mm' } }, grid: { color: c.grid } },
          y: { ticks: { callback: (_v, i) => scanTypes[i] || '' }, grid: { color: c.grid }, min: -0.5, max: Math.max(0, scanTypes.length - 0.5) },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const a = ctx.raw._meta;
                return `${a.scan_type} · risk ${a.risk_score?.toFixed?.(1) || a.risk_score}`;
              },
              title: (items) => items[0]?.raw?.x || '',
            },
          },
        },
        onClick: (_e, items) => {
          if (items[0]) {
            const a = items[0].raw._meta;
            openAttackDrawer(a.attack_id);
          }
        },
      },
    });
  }

  // Packet timeline — line of count per bucket
  const buckets = new Map();
  data.packets.forEach((p) => {
    const k = p.time;
    buckets.set(k, (buckets.get(k) || 0) + 1);
  });
  const sortedKeys = Array.from(buckets.keys()).sort();
  if (tlChartPackets) tlChartPackets.destroy();
  const ctx2 = document.getElementById('chart-tl-packets');
  if (ctx2) {
    tlChartPackets = new Chart(ctx2, {
      type: 'line',
      data: {
        labels: sortedKeys,
        datasets: [{
          label: 'packets/5min',
          data: sortedKeys.map((k) => buckets.get(k)),
          borderColor: c.accent, backgroundColor: c.accentSoft, fill: true, tension: 0.3, pointRadius: 2,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: { x: { grid: { color: c.grid } }, y: { grid: { color: c.grid }, beginAtZero: true } },
        plugins: { legend: { display: false } },
      },
    });
  }

  // List of attack dots for non-chart users
  const list = document.getElementById('tl-attacks-list');
  if (list) {
    if (!data.attacks.length) {
      list.innerHTML = '<div style="color:var(--c-text-4);font-size:12px;padding:8px 0">No attacks in this window.</div>';
    } else {
      list.innerHTML = data.attacks.map((a) => `
        <div class="tl-attack-row" data-attack-id="${escapeHtml(a.attack_id)}"
             style="display:flex;align-items:center;gap:10px;padding:7px 10px;border:1px solid var(--c-border);border-radius:var(--r-sm);background:var(--c-surface-2);cursor:pointer">
          <span style="font-size:11.5px;color:var(--c-text-3);font-family:'JetBrains Mono',monospace">${fmt.shortTime(a.time)}</span>
          <span class="risk-pill ${escapeHtml(a.risk_level)}">${escapeHtml(a.risk_level)}</span>
          <span style="font-size:12.5px;color:var(--c-text-2)">${escapeHtml(a.scan_type)}</span>
          <span style="margin-left:auto;font-size:11.5px;color:var(--c-text-4)">risk ${a.risk_score?.toFixed?.(1) || a.risk_score}</span>
        </div>
      `).join('');
      list.querySelectorAll('.tl-attack-row').forEach((row) => {
        row.addEventListener('click', () => openAttackDrawer(parseInt(row.dataset.attackId, 10)));
      });
    }
  }
}

function initTimeline() {
  document.getElementById('btn-tl-load')?.addEventListener('click', loadTimeline);
  document.getElementById('tl-ip-input')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') loadTimeline();
  });
  // Wire Top Sources rows → click to jump to timeline
  document.getElementById('top-sources')?.addEventListener('click', (e) => {
    const ip = e.target.closest('[data-source-ip]')?.dataset.sourceIp;
    if (!ip) return;
    document.getElementById('tl-ip-input').value = ip;
    location.hash = '#sec-source-timeline';
    loadTimeline();
  });
}

// ---- Topology: tiny force-directed renderer on a canvas -----------------
// ponytail: native canvas + Verlet-style sim. No D3. O(n²) per tick — fine
// for <500 nodes, the realistic cap from the dashboard's last-24h window.
const topo = {
  nodes: [], edges: [], animating: false,
  canvas: null, ctx: null, hover: null,
  width: 0, height: 0,
};

function riskColor(level) {
  const c = getColors();
  return c.risk[level] || c.accent;
}

function tickTopo() {
  if (!topo.animating) return;
  const { nodes, width, height } = topo;
  const cx = width / 2, cy = height / 2;
  // Repulsion
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      const dx = a.x - b.x, dy = a.y - b.y;
      const d2 = dx * dx + dy * dy + 0.01;
      const d = Math.sqrt(d2);
      const f = 1200 / d2;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
    }
  }
  // Spring along edges
  topo.edges.forEach(({ src, dst, weight }) => {
    const a = nodes[src], b = nodes[dst];
    if (!a || !b) return;
    const dx = b.x - a.x, dy = b.y - a.y;
    const d = Math.sqrt(dx * dx + dy * dy) + 0.01;
    const target = 90 + Math.log2(weight + 1) * 14;
    const f = (d - target) * 0.04;
    const fx = (dx / d) * f, fy = (dy / d) * f;
    a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
  });
  // Gravity + integrate + damp
  nodes.forEach((n) => {
    n.vx += (cx - n.x) * 0.002;
    n.vy += (cy - n.y) * 0.002;
    n.vx *= 0.82; n.vy *= 0.82;
    n.x += n.vx; n.y += n.vy;
    n.x = Math.max(20, Math.min(width - 20, n.x));
    n.y = Math.max(20, Math.min(height - 20, n.y));
  });
  drawTopo();
  requestAnimationFrame(tickTopo);
}

function drawTopo() {
  const { ctx, nodes, edges, width, height, hover } = topo;
  if (!ctx) return;
  ctx.clearRect(0, 0, width, height);
  // edges
  edges.forEach(({ src, dst, weight, scanTypes }) => {
    const a = nodes[src], b = nodes[dst];
    if (!a || !b) return;
    ctx.strokeStyle = 'rgba(150,160,180,0.18)';
    ctx.lineWidth = Math.min(4, 0.5 + Math.log2(weight + 1) * 0.6);
    ctx.beginPath();
    ctx.moveTo(a.x, a.y);
    ctx.lineTo(b.x, b.y);
    ctx.stroke();
  });
  // nodes
  nodes.forEach((n, i) => {
    const r = Math.max(4, Math.min(28, 4 + Math.sqrt(n.size) * 0.5));
    ctx.beginPath();
    ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = riskColor(n.riskLevel);
    ctx.fill();
    if (i === hover) {
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 2;
      ctx.stroke();
    }
  });
  // labels for hovered node
  if (hover !== null && nodes[hover]) {
    const n = nodes[hover];
    const r = Math.max(4, Math.min(28, 4 + Math.sqrt(n.size) * 0.5));
    ctx.font = '11px Inter, system-ui, sans-serif';
    const label = `${n.label}${n.tool ? ' · ' + n.tool : ''}`;
    const w = ctx.measureText(label).width + 12;
    ctx.fillStyle = 'rgba(15,18,25,0.92)';
    ctx.fillRect(n.x + r + 6, n.y - 12, w, 24);
    ctx.fillStyle = '#E6EDF7';
    ctx.fillText(label, n.x + r + 12, n.y + 4);
  }
}

async function loadTopology() {
  const data = await API.get('/api/topology');
  const empty = document.getElementById('topo-empty');
  const stats = document.getElementById('topo-stats');
  if (!data || !data.ok || !data.nodes?.length) {
    if (empty) empty.style.display = 'flex';
    topo.nodes = []; topo.edges = [];
    drawTopo();
    if (stats) stats.textContent = '0 nodes';
    renderTopoLegend([]);
    return;
  }
  if (empty) empty.style.display = 'none';
  if (stats) stats.textContent = `${data.nodes.length} nodes · ${data.edges.length} edges`;
  renderTopoLegend(data.nodes);

  // Layout: sources left, targets right; spread vertically by index
  const sources = data.nodes.filter((n) => n.type === 'source');
  const targets = data.nodes.filter((n) => n.type === 'target');
  const rect = topo.canvas.getBoundingClientRect();
  topo.width = rect.width; topo.height = rect.height;
  topo.canvas.width = rect.width * devicePixelRatio;
  topo.canvas.height = rect.height * devicePixelRatio;
  topo.ctx.scale(devicePixelRatio, devicePixelRatio);

  const nodes = [];
  const idIndex = {};
  sources.forEach((n, i) => {
    idIndex[n.id] = nodes.length;
    nodes.push({
      ...n,
      x: topo.width * 0.18 + (i % 2 ? 60 : 0),
      y: (i + 1) * (topo.height / (sources.length + 1)) + (Math.random() - 0.5) * 20,
      vx: 0, vy: 0, riskLevel: n.risk >= 7 ? 'critical' : n.risk >= 5 ? 'high' : n.risk >= 3 ? 'medium' : 'low',
    });
  });
  targets.forEach((n, i) => {
    if (idIndex[n.id] !== undefined) return;
    idIndex[n.id] = nodes.length;
    nodes.push({
      ...n,
      x: topo.width * 0.78 + (i % 2 ? -40 : 0),
      y: (i + 1) * (topo.height / (targets.length + 1)) + (Math.random() - 0.5) * 20,
      vx: 0, vy: 0, riskLevel: 'low',
    });
  });
  topo.nodes = nodes;
  topo.edges = data.edges
    .filter((e) => idIndex[e.source] !== undefined && idIndex[e.target] !== undefined)
    .map((e) => ({ src: idIndex[e.source], dst: idIndex[e.target], weight: e.weight || 1, scanTypes: e.scan_types || [] }));

  if (!topo.animating) {
    topo.animating = true;
    requestAnimationFrame(tickTopo);
  }
}

function renderTopoLegend(nodes) {
  const host = document.getElementById('topo-legend');
  if (!host) return;
  const counts = { source: 0, target: 0, critical: 0, high: 0 };
  nodes.forEach((n) => {
    counts[n.type] = (counts[n.type] || 0) + 1;
    if (n.risk >= 7) counts.critical++;
    else if (n.risk >= 5) counts.high++;
  });
  host.innerHTML = `
    <span><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--c-accent);vertical-align:middle"></span> ${counts.source} source${counts.source === 1 ? '' : 's'}</span>
    <span><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:#94A3B8;vertical-align:middle"></span> ${counts.target} target${counts.target === 1 ? '' : 's'}</span>
    <span style="color:var(--c-critical)">● ${counts.critical} critical</span>
    <span style="color:var(--c-high)">● ${counts.high} high-risk</span>
  `;
}

function initTopology() {
  topo.canvas = document.getElementById('canvas-topology');
  if (!topo.canvas) return;
  topo.ctx = topo.canvas.getContext('2d');

  // Hover detection (throttled to mousemove)
  topo.canvas.addEventListener('mousemove', (e) => {
    const rect = topo.canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    let found = -1;
    for (let i = 0; i < topo.nodes.length; i++) {
      const n = topo.nodes[i];
      const r = Math.max(4, Math.min(28, 4 + Math.sqrt(n.size) * 0.5)) + 2;
      if ((mx - n.x) ** 2 + (my - n.y) ** 2 <= r * r) { found = i; break; }
    }
    if (found !== topo.hover) { topo.hover = found; topo.canvas.style.cursor = found >= 0 ? 'pointer' : 'default'; }
  });
  topo.canvas.addEventListener('click', () => {
    if (topo.hover != null && topo.hover >= 0) {
      const n = topo.nodes[topo.hover];
      if (n && n.type === 'source') {
        document.getElementById('tl-ip-input').value = n.id;
        location.hash = '#sec-source-timeline';
        loadTimeline();
      }
    }
  });
  window.addEventListener('resize', () => {
    if (topo.nodes.length) loadTopology();
  });

  document.getElementById('btn-topo-refresh')?.addEventListener('click', loadTopology);
}

// ---- Section-aware loading: load the right panel when user navigates -----
const sectionLoaders = {
  'sec-schedules': loadSchedules,
  'sec-topology': loadTopology,
};
function initSectionRouting() {
  const navLinks = document.querySelectorAll('.nav-link');
  navLinks.forEach((a) => {
    a.addEventListener('click', () => {
      const id = a.getAttribute('href')?.replace('#', '');
      if (id && sectionLoaders[id]) setTimeout(sectionLoaders[id], 50);
    });
  });
  // Also load on first paint if the section is already in the URL
  const initial = location.hash.replace('#', '');
  if (initial && sectionLoaders[initial]) sectionLoaders[initial]();
}

function bootPhase3() {
  try { initSchedules(); } catch (e) { console.error('initSchedules failed', e); }
  try { initTimeline(); } catch (e) { console.error('initTimeline failed', e); }
  try { initTopology(); } catch (e) { console.error('initTopology failed', e); }
  try { initSectionRouting(); } catch (e) { console.error('initSectionRouting failed', e); }
}
bootPhase3();
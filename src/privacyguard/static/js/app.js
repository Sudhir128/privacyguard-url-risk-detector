const RISK_COLORS = {
  LOW: "#0ca30c",
  MEDIUM: "#fab219",
  HIGH: "#ec835a",
  CRITICAL: "#d03b3b",
};
const RISK_ICONS = { LOW: "✅", MEDIUM: "⚠️", HIGH: "🔶", CRITICAL: "🚨" };
const RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${res.status})`);
  }
  return res.json();
}

function badge(label) {
  const icon = RISK_ICONS[label] || "•";
  return `<span class="badge badge-${label}">${icon} ${label}</span>`;
}

function timeAgo(iso) {
  if (!iso) return "";
  const date = new Date(iso.endsWith("Z") ? iso : iso + "Z");
  const diffMs = Date.now() - date.getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

/* ---------------- Tabs ---------------- */

function initTabs() {
  const buttons = document.querySelectorAll(".tab-btn");
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      buttons.forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");

      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");

      if (btn.dataset.tab === "dashboard") loadDashboard();
    });
  });
}

/* ---------------- Status indicator ---------------- */

async function checkHealth() {
  const dot = document.getElementById("statusDot");
  const text = document.getElementById("statusText");
  try {
    const health = await api("/api/health");
    dot.className = "status-dot ok";
    text.textContent = `Online · ${health.tracker_domains_loaded.toLocaleString()} trackers loaded`;
  } catch (err) {
    dot.className = "status-dot down";
    text.textContent = "API unreachable";
  }
}

/* ---------------- Scanner tab ---------------- */

function renderScanResult(result) {
  const wrap = document.getElementById("scanResult");
  const confidencePct = Math.round(result.confidence * 100);

  wrap.innerHTML = `
    <div class="glass-card">
      <div class="result-head">
        <div>${badge(result.risk_label)}</div>
        <div class="result-url">${result.url}</div>
      </div>

      <div class="confidence-row">
        <div class="confidence-label"><span>Model confidence</span><span>${confidencePct}%</span></div>
        <div class="confidence-track"><div class="confidence-fill" style="width:${confidencePct}%"></div></div>
      </div>

      <div class="result-grid">
        <div class="result-fact">
          <span class="fact-label">Risk score</span>
          <span class="fact-value">${result.risk_score.toFixed(1)} / 10</span>
        </div>
        <div class="result-fact">
          <span class="fact-label">Verdict</span>
          <span class="fact-value">${result.verdict}</span>
        </div>
        <div class="result-fact">
          <span class="fact-label">Tracker domain</span>
          <span class="fact-value">${result.is_tracker ? "Yes ⚠️" : "No ✅"}</span>
        </div>
        <div class="result-fact">
          <span class="fact-label">Phishing pattern</span>
          <span class="fact-value">${result.is_phishing ? `Detected 🚨${result.matched_brand ? ` (mimics ${result.matched_brand})` : ""}` : "None found ✅"}</span>
        </div>
      </div>

      ${result.explanation.length ? `<ul class="reasons-list">${result.explanation.map((r) => `<li>${r}</li>`).join("")}</ul>` : ""}
    </div>
  `;
  wrap.hidden = false;
}

function initScanForm() {
  const form = document.getElementById("scanForm");
  const btn = document.getElementById("scanBtn");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const url = document.getElementById("urlInput").value.trim();
    if (!url) return;

    setBtnLoading(btn, true);
    try {
      const result = await api("/api/scan/url", {
        method: "POST",
        body: JSON.stringify({ url }),
      });
      renderScanResult(result);
    } catch (err) {
      alert(`Scan failed: ${err.message}`);
    } finally {
      setBtnLoading(btn, false);
    }
  });
}

function setBtnLoading(btn, loading) {
  btn.disabled = loading;
  btn.querySelector(".btn-label").hidden = loading;
  btn.querySelector(".btn-spinner").hidden = !loading;
}

/* ---------------- Dashboard tab ---------------- */

let donutChart = null;
let trackerChart = null;
let currentScanController = null;
let showAllHistory = false;

async function loadDashboard() {
  await Promise.all([loadStats(), loadTopTrackers(), loadHistory()]);
}

async function loadStats() {
  const stats = await api("/api/stats");

  document.getElementById("statTotalScans").textContent = stats.total_scans.toLocaleString();
  document.getElementById("statPrivacyScore").textContent = `${stats.privacy_score}/100`;
  document.getElementById("statTrackers").textContent = stats.trackers_found.toLocaleString();
  document.getElementById("statCritical").textContent = stats.critical_alerts.toLocaleString();

  renderDonut(stats.risk_distribution);
}

function renderDonut(distribution) {
  const labels = RISK_ORDER;
  const values = labels.map((l) => distribution[l] || 0);
  const colors = labels.map((l) => RISK_COLORS[l]);
  const total = values.reduce((a, b) => a + b, 0);

  const legend = document.getElementById("donutLegend");
  legend.innerHTML = labels
    .map(
      (l, i) => `
      <li>
        <span class="legend-swatch" style="background:${colors[i]}"></span>
        ${RISK_ICONS[l]} ${l}
        <span class="legend-count">${values[i]}</span>
      </li>`
    )
    .join("");

  const tableBody = document.getElementById("distTableBody");
  tableBody.innerHTML = labels.map((l, i) => `<tr><td>${l}</td><td>${values[i]}</td></tr>`).join("");

  const ctx = document.getElementById("riskDonut");
  const data = {
    labels: labels.map((l) => `${l} (${RISK_ICONS[l]})`),
    datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }],
  };

  if (donutChart) {
    donutChart.data = data;
    donutChart.update();
    return;
  }

  donutChart = new Chart(ctx, {
    type: "doughnut",
    data,
    options: {
      cutout: "68%",
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => {
              const pct = total ? Math.round((ctx.parsed / total) * 100) : 0;
              return ` ${ctx.label}: ${ctx.parsed} (${pct}%)`;
            },
          },
        },
      },
    },
  });
}

async function loadTopTrackers() {
  const trackers = await api("/api/stats/trackers?limit=10");
  const ctx = document.getElementById("trackerBar");

  const labels = trackers.map((t) => t.domain);
  const values = trackers.map((t) => t.count);

  const data = {
    labels,
    datasets: [{ data: values, backgroundColor: "#00d4ff", borderRadius: 4, maxBarThickness: 22 }],
  };

  if (trackerChart) {
    trackerChart.data = data;
    trackerChart.update();
    return;
  }

  trackerChart = new Chart(ctx, {
    type: "bar",
    data,
    options: {
      indexAxis: "y",
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: "rgba(255,255,255,0.08)" }, ticks: { color: "#7c88a8" } },
        y: { grid: { display: false }, ticks: { color: "#b8c1d9" } },
      },
    },
  });
}

async function loadHistory() {
  const limit = showAllHistory ? 10000 : 25;
  const history = await api(`/api/history?limit=${limit}`);
  const body = document.getElementById("historyTableBody");

  if (!history.items.length) {
    body.innerHTML = `<tr><td colspan="5" class="empty-row">No scans yet.</td></tr>`;
    return;
  }
  
  let itemsToDisplay = history.items;
  if (showAllHistory) {
    itemsToDisplay = itemsToDisplay.sort((a, b) => {
      return RISK_ORDER.indexOf(b.risk_label) - RISK_ORDER.indexOf(a.risk_label);
    });
  }

  body.innerHTML = itemsToDisplay
    .map(
      (item) => `
      <tr>
        <td class="url-cell" title="${item.url}">${item.url}</td>
        <td>${badge(item.risk_label)}</td>
        <td>${Number(item.score).toFixed(1)}</td>
        <td>${item.is_tracker ? "Yes" : "No"}</td>
        <td>${timeAgo(item.created_at)}</td>
      </tr>`
    )
    .join("");
    
  document.getElementById("seeAllHistoryBtn").textContent = showAllHistory ? "Show Recent" : "See All";
}

function initDashboardControls() {
  document.getElementById("refreshHistory").addEventListener("click", loadHistory);
  document.getElementById("seeAllHistoryBtn").addEventListener("click", () => {
    showAllHistory = !showAllHistory;
    loadHistory();
  });
  document.getElementById("toggleDistTable").addEventListener("click", () => {
    const table = document.getElementById("distTable");
    table.hidden = !table.hidden;
  });

  const browserBtn = document.getElementById("browserScanBtn");
  const stopBtn = document.getElementById("browserScanStopBtn");

  stopBtn.addEventListener("click", () => {
    if (currentScanController) {
      currentScanController.abort();
    }
  });

  browserBtn.addEventListener("click", async () => {
    const browser = document.getElementById("browserSelect").value || null;
    const progress = document.getElementById("browserScanProgress");
    const noteEl = document.getElementById("browserScanResultText");

    setBtnLoading(browserBtn, true);
    stopBtn.hidden = false;
    progress.hidden = false;
    noteEl.textContent = "";
    
    currentScanController = new AbortController();

    try {
      const result = await api("/api/scan/browser", {
        method: "POST",
        body: JSON.stringify({ browser }),
        signal: currentScanController.signal
      });
      noteEl.textContent = `Scanned ${result.total_urls} URLs from browser history.`;
      await loadDashboard();
    } catch (err) {
      if (err.name === 'AbortError') {
        noteEl.textContent = "Browser scan stopped.";
      } else {
        noteEl.textContent = `Browser scan failed: ${err.message}`;
      }
    } finally {
      setBtnLoading(browserBtn, false);
      stopBtn.hidden = true;
      progress.hidden = true;
      currentScanController = null;
    }
  });

  document.getElementById("statCriticalTile").addEventListener("click", loadCriticalModal);
  document.getElementById("closeCriticalModal").addEventListener("click", () => {
    document.getElementById("criticalModal").hidden = true;
  });
}

async function loadCriticalModal() {
  const modal = document.getElementById("criticalModal");
  const body = document.getElementById("criticalModalBody");
  modal.hidden = false;
  body.innerHTML = `<tr><td colspan="4" class="empty-row">Loading...</td></tr>`;
  
  try {
    const history = await api("/api/history?limit=10000&risk_label=CRITICAL");
    if (!history.items.length) {
      body.innerHTML = `<tr><td colspan="4" class="empty-row">No critical alerts found.</td></tr>`;
      return;
    }
    
    body.innerHTML = history.items
      .map(
        (item) => `
        <tr>
          <td class="url-cell" title="${item.url}">${item.url}</td>
          <td>${Number(item.score).toFixed(1)}</td>
          <td>${item.is_phishing ? `🚨` : "No"}</td>
          <td>${timeAgo(item.created_at)}</td>
        </tr>`
      )
      .join("");
  } catch (err) {
    body.innerHTML = `<tr><td colspan="4" class="empty-row" style="color:var(--status-critical)">Failed to load: ${err.message}</td></tr>`;
  }
}

/* ---------------- Init ---------------- */

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initScanForm();
  initDashboardControls();
  checkHealth();
  setInterval(checkHealth, 30000);
});

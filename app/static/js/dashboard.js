// Vanilla-JS poller for the SentinelWall SOC dashboard. No frameworks, no build step.

const STATUS_CLASS = {
  Active: "pill-active",
  Safe: "pill-safe",
  Degraded: "pill-degraded",
};

function formatTTL(seconds) {
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}m ${s}s`;
}

async function refreshStatus() {
  const res = await fetch("/api/v1/dashboard/status");
  if (!res.ok) return;
  const data = await res.json();
  const pill = document.getElementById("status-pill");
  pill.textContent = data.degraded_reason ? `${data.status} — ${data.degraded_reason}` : data.status;
  pill.className = STATUS_CLASS[data.status] || "";
}

async function refreshAlerts() {
  const res = await fetch("/api/v1/dashboard/alerts?limit=30");
  if (!res.ok) return;
  const alerts = await res.json();
  const ticker = document.getElementById("alert-ticker");
  ticker.innerHTML = alerts.length
    ? alerts
        .map(
          (a) => `
      <div class="alert">
        <div class="alert-top"><span>#${a.id} · ${a.received_at}</span><span>${a.severity}</span></div>
        <div class="alert-title">${a.threat_type}</div>
        <div class="alert-sub">${a.resource_affected} · ${a.compromised_ip} · ${a.action_taken}</div>
      </div>`
        )
        .join("")
    : `<div class="empty">No alerts yet.</div>`;
}

async function refreshBlocks() {
  const res = await fetch("/api/v1/dashboard/blocks");
  if (!res.ok) return;
  const blocks = await res.json();
  const tbody = document.getElementById("blocks-table");
  tbody.innerHTML = blocks.length
    ? blocks
        .map(
          (b) => `
      <tr>
        <td class="ip">${b.ip}</td>
        <td class="muted">${b.blocked_at}</td>
        <td>${formatTTL(b.ttl_remaining_seconds)}</td>
        <td class="muted">#${b.source_alert_id}</td>
      </tr>`
        )
        .join("")
    : `<tr><td colspan="4" class="empty">No active containments.</td></tr>`;
}

async function tick() {
  await Promise.all([refreshStatus(), refreshAlerts(), refreshBlocks()]);
}

// Demo mode: reveal the banner + "Simulate attack" button only when the server
// reports demo mode is on. The button drives the same pipeline as a real alert.
async function initDemo() {
  try {
    const res = await fetch("/api/v1/demo/status");
    if (!res.ok) return;
    const { enabled } = await res.json();
    if (!enabled) return;
    document.getElementById("demo-banner")?.classList.remove("hidden");
    const btn = document.getElementById("sim-btn");
    if (!btn) return;
    btn.classList.remove("hidden");
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        await fetch("/api/v1/demo/simulate", { method: "POST" });
        await new Promise((r) => setTimeout(r, 500)); // let the worker process it
        await tick();
      } finally {
        btn.disabled = false;
      }
    });
  } catch {
    /* demo endpoint unavailable — leave controls hidden */
  }
}

initDemo();
tick();
setInterval(tick, 5000);

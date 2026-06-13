// Vanilla-JS poller for the SentinelWall SOC dashboard. No frameworks, no build step.

const STATUS_COLORS = {
  Active: "bg-amber-600",
  Safe: "bg-emerald-600",
  Degraded: "bg-red-600",
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
  pill.className = `px-3 py-1 rounded-full text-sm font-semibold ${STATUS_COLORS[data.status] || "bg-slate-700"}`;
}

async function refreshAlerts() {
  const res = await fetch("/api/v1/dashboard/alerts?limit=30");
  if (!res.ok) return;
  const alerts = await res.json();
  const ticker = document.getElementById("alert-ticker");
  ticker.innerHTML = alerts
    .map(
      (a) => `
      <div class="border border-slate-800 rounded p-2">
        <div class="flex justify-between text-slate-400 text-xs">
          <span>#${a.id} · ${a.received_at}</span>
          <span>${a.severity}</span>
        </div>
        <div class="font-semibold">${a.threat_type}</div>
        <div class="text-slate-400 text-xs">${a.resource_affected} · ${a.compromised_ip} · ${a.action_taken}</div>
      </div>`
    )
    .join("");
}

async function refreshBlocks() {
  const res = await fetch("/api/v1/dashboard/blocks");
  if (!res.ok) return;
  const blocks = await res.json();
  const tbody = document.getElementById("blocks-table");
  tbody.innerHTML = blocks
    .map(
      (b) => `
      <tr class="border-t border-slate-800">
        <td class="py-1">${b.ip}</td>
        <td class="py-1 text-slate-400">${b.blocked_at}</td>
        <td class="py-1">${formatTTL(b.ttl_remaining_seconds)}</td>
        <td class="py-1 text-slate-400">#${b.source_alert_id}</td>
      </tr>`
    )
    .join("");
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

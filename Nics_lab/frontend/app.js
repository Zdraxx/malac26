const $ = (id) => document.getElementById(id);
let currentScan = null;

function setMessage(text, error = false) {
  $("message").textContent = text;
  $("message").className = error ? "message error" : "message";
}

function renderPorts(ports) {
  const body = $("ports-body");
  if (!ports.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No hay puertos registrados.</td></tr>';
    return;
  }
  body.innerHTML = ports.map(p => `<tr>
    <td><strong>${p.port}</strong></td>
    <td class="status-${p.status}">${p.status}</td>
    <td><span class="badge">${p.family || "unknown"}</span></td>
    <td>${p.latency_ms == null ? "—" : `${p.latency_ms.toFixed(1)} ms`}</td>
    <td>${p.status === "open" ? `<button class="action" onclick="collectPort(${p.port})">Recolectar</button>` : ""} <button class="action" onclick="showDetail(${p.port})">Ver →</button></td>
  </tr>`).join("");
  $("open-count").textContent = ports.filter(p => p.status === "open").length;
}

async function refreshScan() {
  if (!currentScan) return;
  const scan = await fetch(`/api/scan/${currentScan}`).then(r => r.json());
  $("scan-status").textContent = scan.status;
  renderPorts(scan.ports);
  if (scan.status === "running" || scan.status === "queued") setTimeout(refreshScan, 700);
  else setMessage(`Escaneo ${scan.status}. Selecciona un puerto para recolectar evidencias.`);
}

async function showDetail(port) {
  $("detail-title").textContent = `Puerto ${port}`;
  const data = await fetch(`/api/port/${port}`).then(r => r.json());
  $("request-count").textContent = data.requests.length;
  $("clue-count").textContent = data.clues.length;
  $("observation-count").textContent = data.observations.length;
  $("detail").innerHTML = `<div class="evidence">
    <div><span>FAMILIA</span><strong>${data.family}</strong></div>
    <div><span>REQUESTS</span><strong>${data.requests.length}</strong></div>
    <div><span>CLUES</span><strong>${data.clues.length}</strong></div>
    <div><span>OBSERVACIONES</span><strong>${data.observations.length}</strong></div>
  </div>
  <a class="api-link" href="/api/port/${port}/report" target="_blank">Descargar informe Markdown ↗</a>
  <h3>Observaciones</h3>
  ${data.observations.slice(0, 8).map(o => `<div class="obs"><small>${o.tipo}</small><br>${o.descripcion}<br><span class="muted">${o.sugerencia}</span></div>`).join("") || '<p class="muted">Sin observaciones todavía.</p>'}`;
}

async function collectPort(port) {
  setMessage(`Recolectando evidencias del puerto ${port}…`);
  const response = await fetch(`/api/collect/${port}`, {method: "POST"});
  const data = await response.json();
  if (!response.ok) { setMessage(data.detail || "No se pudo iniciar la recolección.", true); return; }
  setMessage(`Recolección iniciada para ${port}. Puedes abrir el detalle cuando termine.`);
  setTimeout(async () => { await showDetail(port); if (currentScan) refreshScan(); }, 1200);
}

$("scan-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage("Lanzando escaneo…");
  const response = await fetch("/api/scan", {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({
    target: $("target").value.trim(), ports: $("ports").value.trim(), concurrency: Number($("concurrency").value)
  })});
  const data = await response.json();
  if (!response.ok) { setMessage(data.detail || "No se pudo iniciar el escaneo.", true); return; }
  currentScan = data.id;
  $("scan-status").textContent = "queued";
  refreshScan();
});

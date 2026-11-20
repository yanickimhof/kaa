// Kaa web app. No framework, no external requests, no innerHTML with data.

const CLASS_STYLE = {
  router: ["#3ea0ff", "Router"], access_point: ["#5ac8fa", "Access point"],
  computer: ["#bf8bff", "Computer"], phone: ["#ff7ab6", "Phone"], tablet: ["#ff7ab6", "Tablet"],
  tv: ["#ffb74d", "TV"], media: ["#ffb74d", "Media"], speaker: ["#ffd166", "Speaker"],
  camera: ["#ff6b6b", "Camera"], printer: ["#9ad1a0", "Printer"], nas: ["#4dd0e1", "NAS"],
  game_console: ["#a0e060", "Console"], sensor: ["#64e3b5", "Sensor"], plug: ["#64e3b5", "Plug"],
  light: ["#ffe066", "Light"], thermostat: ["#64e3b5", "Thermostat"], car: ["#e0e0e0", "Vehicle"],
  hub: ["#64e3b5", "Hub"], server: ["#4dd0e1", "Server"], wearable: ["#ff7ab6", "Wearable"],
  iot: ["#64e3b5", "IoT"], unknown: ["#6b7587", "Unknown"],
};
const SEV_COLOR = { critical: "#ff453a", high: "#ff9f0a", medium: "#ffd60a", low: "#3ea0ff", info: "#8a94a6" };
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const NS = "http://www.w3.org/2000/svg";

let token = "";
let devices = [];
let findings = [];
let openId = null;

const $ = (id) => document.getElementById(id);
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n;
}
function svg(tag, attrs = {}, ...kids) {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  for (const k of kids) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n;
}
async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.method && opts.method !== "GET" ? { "X-Kaa-Token": token } : {}) };
  const r = await fetch(path, { ...opts, headers });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
const name = (d) => d.label || d.hostname || d.vendor || d.mac;
const short = (d) => d.label || d.hostname || (d.class !== "unknown" ? `${clsStyle(d.class)[1]} .${(d.ip || "").split(".").pop()}` : (d.ip || d.mac));
const clsStyle = (c) => CLASS_STYLE[c] || CLASS_STYLE.unknown;
const ago = (iso) => {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  return s < 60 ? "just now" : s < 3600 ? `${Math.floor(s / 60)} min ago` : s < 86400 ? `${Math.floor(s / 3600)} h ago` : `${Math.floor(s / 86400)} d ago`;
};
const worst = (id) => findings.filter((f) => f.device_id === id && f.status === "open")
  .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity])[0];

/* ---------- overview ---------- */
function renderOverview(o) {
  const v = o.score.value;
  $("score").textContent = v;
  $("grade").textContent = o.score.grade;
  const ring = $("ring");
  ring.style.strokeDashoffset = 364.4 * (1 - v / 100);
  ring.style.stroke = v >= 90 ? "var(--ok)" : v >= 75 ? "var(--accent)" : v >= 50 ? "var(--warn)" : "var(--crit)";
  $("k-online").textContent = o.online;
  $("k-devices").textContent = o.devices;
  $("k-unknown").textContent = o.unidentified;
  $("scope").textContent = (o.state.scope || []).join(", ") || "scope pending";
  const st = $("status");
  st.className = "status " + (o.state.running ? "running" : o.state.last_error ? "err" : "ok");
  $("status-text").textContent = o.state.running ? "Scanning" : o.state.last_error ? o.state.last_error : `Updated ${ago(o.state.last_run)}`;
  $("scan").disabled = $("deep").disabled = o.state.running;
  const h = o.history.map((p) => p.value);
  const sp = $("spark");
  sp.replaceChildren();
  if (h.length > 1) {
    const pts = h.map((y, i) => `${(i / (h.length - 1)) * 240},${36 - (y / 100) * 34 - 1}`);
    sp.append(svg("path", { d: "M" + pts.join(" L") }));
  }
}

/* ---------- actions ---------- */
function renderActions() {
  const box = $("actions");
  box.replaceChildren();
  const open = findings.filter((f) => f.status === "open" && f.severity !== "info")
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]).slice(0, 5);
  if (!open.length) {
    box.append(el("div", { class: "empty" }, "Nothing to do. Kaa found no open issues."));
    return;
  }
  for (const f of open) {
    box.append(el("div", { class: `action sev-${f.severity}`, onclick: () => f.device_id && openDrawer(f.device_id) },
      el("div", { class: "t" }, f.title),
      el("div", { class: "f" }, f.fix),
      el("div", { class: "row" }, el("span", { class: `badge ${f.severity}` }, f.severity),
        el("button", { class: "btn ghost small", onclick: (e) => { e.stopPropagation(); ack(f.id); } }, "Acknowledge"))));
  }
}
async function ack(id, undo = false) {
  await api(`/api/findings/${id}/ack${undo ? "?undo=true" : ""}`, { method: "POST" });
  await refresh();
}

/* ---------- map ---------- */
function renderMap() {
  const s = $("map");
  s.replaceChildren();
  const cx = 410, cy = 210;
  const hub = devices.find((d) => d.role === "gateway");
  const others = devices.filter((d) => d !== hub)
    .sort((a, b) => a.class.localeCompare(b.class) || (a.ip || "").localeCompare(b.ip || "", undefined, { numeric: true }));
  const rings = others.length > 16 ? [[135, Math.ceil(others.length / 2)], [195, others.length]] : [[160, others.length]];
  const pos = new Map();
  let idx = 0;
  rings.forEach(([r, cap], ri) => {
    const items = others.slice(idx, idx + (ri === 0 && rings.length > 1 ? cap : others.length));
    items.forEach((d, i) => {
      const a = (i / items.length) * Math.PI * 2 - Math.PI / 2 + ri * 0.2;
      pos.set(d.id, [cx + Math.cos(a) * r * 1.35, cy + Math.sin(a) * r * 0.98]);
    });
    idx += items.length;
  });
  const edges = svg("g"), nodes = svg("g");
  for (const d of others) {
    const [x, y] = pos.get(d.id);
    edges.append(svg("line", { x1: cx, y1: cy, x2: x, y2: y, class: "edge" + (d.online ? " on" : "") }));
    const w = worst(d.id);
    const col = clsStyle(d.class)[0];
    const g = svg("g", { class: "node" + (d.online ? "" : " off"), transform: `translate(${x} ${y})` });
    g.addEventListener("click", () => openDrawer(d.id));
    if (w && w.rule_id === "KAA-NEW-DEVICE") g.append(svg("circle", { r: 14, class: "new-pulse" }));
    if (w && w.severity !== "info") g.append(svg("circle", { r: 17, class: "halo", stroke: SEV_COLOR[w.severity] }));
    g.append(svg("circle", { r: 12, class: "body", fill: col, "fill-opacity": ".9" }),
      svg("text", { y: 28 }, short(d).slice(0, 18)), svg("title", {}, `${name(d)} · ${d.ip || ""}`));
    nodes.append(g);
  }
  s.append(edges, nodes);
  const hubG = svg("g", { transform: `translate(${cx} ${cy})`, style: "cursor:pointer" });
  hubG.addEventListener("click", () => hub && openDrawer(hub.id));
  hubG.append(svg("circle", { r: 36, fill: "var(--panel-2)", stroke: "var(--accent-2)", "stroke-width": 2 }),
    svg("circle", { r: 46, fill: "none", stroke: "var(--accent-2)", "stroke-opacity": ".25" }),
    svg("text", { class: "hub-text", y: 4 }, hub ? "Gateway" : "Network"));
  s.append(hubG);

  const used = [...new Set(devices.map((d) => d.class))];
  $("legend").replaceChildren(...used.map((c) => el("span", {}, el("i", { style: `background:${clsStyle(c)[0]}` }), clsStyle(c)[1])));
}

/* ---------- devices table ---------- */
function renderTable() {
  const q = $("q").value.trim().toLowerCase();
  const f = $("filter").value;
  const rows = devices.filter((d) => {
    const hay = [name(d), d.ip, d.vendor, d.mac, d.class].join(" ").toLowerCase();
    if (q && !hay.includes(q)) return false;
    if (f === "online") return d.online;
    if (f === "unknown") return d.class === "unknown";
    if (f === "attention") return !!worst(d.id) && worst(d.id).severity !== "info";
    return true;
  });
  const tb = document.querySelector("#devices tbody");
  tb.replaceChildren(...rows.map((d) => {
    const w = worst(d.id);
    const [col, label] = clsStyle(d.class);
    return el("tr", { onclick: () => openDrawer(d.id) },
      el("td", {}, el("span", { class: "live" + (d.online ? " on" : "") })),
      el("td", {}, name(d), d.role ? el("span", { class: "badge", style: "margin-left:8px" }, d.role) : null,
        w && w.severity !== "info" ? el("span", { class: "flag", style: `color:${SEV_COLOR[w.severity]}` }, "!") : null),
      el("td", {}, el("span", { class: "pill" }, el("i", { style: `background:${col}` }), label)),
      el("td", { class: "addr" }, d.ip || "–"),
      el("td", { class: "vendor" }, d.vendor || (d.randomized ? "private address" : "–")),
      el("td", {}, el("span", { class: `trust ${d.trust}` }, d.trust)));
  }));
  if (!rows.length) tb.append(el("tr", {}, el("td", { colspan: 6, class: "empty" }, "No devices match.")));
}

/* ---------- drawer ---------- */
async function openDrawer(id) {
  openId = id;
  const d = await api(`/api/devices/${id}`);
  const [col, label] = clsStyle(d.class);
  const dr = $("drawer");
  const seg = el("div", { class: "seg" }, ...["unknown", "known", "guest"].map((t) =>
    el("button", { class: d.trust === t ? "on" : "", onclick: async () => { await save(id, { trust: t }); } }, t)));
  const label_in = el("input", { class: "input", value: d.label || "", placeholder: "Give it a name (kept locally)" });
  label_in.addEventListener("change", () => save(id, { label: label_in.value }));
  dr.replaceChildren(
    el("button", { class: "close", onclick: closeDrawer, "aria-label": "Close" }, "×"),
    el("h3", {}, name(d)),
    el("div", { class: "sub" }, `${d.ip || "no address"} · ${d.mac}`),
    el("div", { class: "block" },
      el("span", { class: "pill" }, el("i", { style: `background:${col}` }), label,
        d.class !== "unknown" ? ` · ${Math.round(d.class_conf * 100)}% · ${d.class_source === "ai" ? "AI hypothesis" : "signatures"}` : "")),
    el("div", { class: "block" }, el("h2", {}, "Name"), label_in),
    el("div", { class: "block" }, el("h2", {}, "Trust"), seg),
    el("div", { class: "block" }, el("h2", {}, "Open issues"), ...(d.findings.length ? d.findings.map(findingCard) : [el("div", { class: "empty" }, "None")])),
    el("div", { class: "block" }, el("h2", {}, "Why Kaa thinks this is a " + label.toLowerCase()),
      ...(d.class_evidence.length ? d.class_evidence.map(evidenceCard) : [el("div", { class: "empty" }, "Not enough evidence yet.")])),
    el("div", { class: "block" }, el("h2", {}, "Facts"),
      el("dl", { class: "kv" }, ...kv([
        ["Vendor", d.vendor || (d.randomized ? "private (randomised) address" : "unknown")],
        ["Hostname", d.hostname], ["First seen", ago(d.first_seen)], ["Last seen", ago(d.last_seen)],
        ["mDNS", (d.facts.mdns_services || []).join(", ")], ["UPnP", d.facts.ssdp_server],
        ["Open ports", (d.facts.open_ports || []).join(", ")]]))));
  dr.classList.add("on"); $("scrim").classList.add("on");
  dr.setAttribute("aria-hidden", "false");
}
const kv = (pairs) => pairs.filter(([, v]) => v).flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]);
function findingCard(f) {
  return el("div", { class: `action sev-${f.severity}`, style: "cursor:default" },
    el("div", { class: "t" }, f.title), el("div", { class: "f" }, f.detail),
    el("div", { class: "f", style: "color:var(--text)" }, "Fix: " + f.fix),
    el("div", { class: "evidence", style: "margin-top:8px" }, el("code", {}, JSON.stringify(f.evidence))),
    el("div", { class: "row" }, el("span", { class: `badge ${f.severity}` }, f.severity),
      el("button", { class: "btn ghost small", onclick: async () => { await ack(f.id, f.status === "ack"); openDrawer(openId); } },
        f.status === "ack" ? "Re-open" : "Acknowledge")));
}
function evidenceCard(e) {
  return el("div", { class: "evidence" }, el("b", {}, e.label), ` (${e.rule})`,
    el("div", { class: "bar-conf" }, el("i", { style: `width:${Math.round(e.confidence * 100)}%` })),
    el("div", {}, el("code", {}, JSON.stringify(e.matched))), e.reason ? el("div", {}, e.reason) : null);
}
async function save(id, patch) {
  await api(`/api/devices/${id}`, { method: "PATCH", body: JSON.stringify(patch) });
  await refresh(); await openDrawer(id);
}
function closeDrawer() {
  $("drawer").classList.remove("on"); $("scrim").classList.remove("on");
  $("drawer").setAttribute("aria-hidden", "true"); openId = null;
}

/* ---------- loop ---------- */
async function refresh() {
  const [o, d, f] = await Promise.all([api("/api/overview"), api("/api/devices"), api("/api/findings")]);
  devices = d; findings = f;
  renderOverview(o); renderActions(); renderMap(); renderTable();
}
async function startScan(ports) {
  await api("/api/scan", { method: "POST", body: JSON.stringify({ ports }) });
  setTimeout(refresh, 600);
}

async function boot() {
  token = (await api("/api/session")).token;
  $("scan").addEventListener("click", () => startScan(false));
  $("deep").addEventListener("click", () => startScan(true));
  $("q").addEventListener("input", renderTable);
  $("filter").addEventListener("change", renderTable);
  $("scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  await refresh();
  setInterval(() => refresh().catch(() => {}), 8000);
}
boot().catch((e) => { $("status-text").textContent = "Cannot reach Kaa: " + e.message; });

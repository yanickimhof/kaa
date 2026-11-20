// Kaa web app. No framework, no external requests, no innerHTML with data.
import { I18N } from "./i18n.js";

let LANG = "fr";
const t = (key, p = {}) => (I18N[LANG][key] ?? I18N.en[key] ?? key).replace(/\{(\w+)\}/g, (_, k) => (p[k] ?? ""));
function applyStatic() {
  document.documentElement.lang = LANG;
  document.querySelectorAll("[data-t]").forEach((n) => { n.textContent = t(n.dataset.t); });
  document.querySelectorAll("[data-tt]").forEach((n) => { n.dataset.tip = t(n.dataset.tt); });
  document.querySelectorAll("[data-ph]").forEach((n) => { n.placeholder = t(n.dataset.ph); });
  setTheme(document.documentElement.dataset.theme);
}

const ICONS = {
  scan: "M21 12a9 9 0 1 1-3-6.7|M21 4v5h-5",
  deep: "M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z|M9 12l2 2 4-4",
  radar: "M12 12l5-5|M3 12a9 9 0 1 0 9-9|M7.5 12a4.5 4.5 0 1 0 4.5-4.5|M12 12h.01",
  check: "M5 12.5l4.5 4.5L19 7",
  minus: "M6 12h12",
  shield: "M12 3l7 3v5c0 5-3 8-7 10-4-2-7-5-7-10V6z|M12 8v4|M12 15h.01",
  gear: "M4 6h9|M17 6h3|M4 12h3|M11 12h9|M4 18h11|M19 18h1|c:15,6,2|c:9,12,2|c:17,18,2",
  sun: "c:12,12,4|M12 2v2|M12 20v2|M4.9 4.9l1.4 1.4|M17.7 17.7l1.4 1.4|M2 12h2|M20 12h2|M4.9 19.1l1.4-1.4|M17.7 6.3l1.4-1.4",
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  auto: "M3 5h18v11H3z|M8 20h8|M12 16v4",
  router: "M5 12a10 10 0 0 1 14 0|M8.5 15.5a5 5 0 0 1 7 0|M12 19h.01",
  computer: "M4 6h16v10H4z|M2 19h20",
  phone: "M8 3h8a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H8a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z|M11 18h2",
  tablet: "M6 3h12v18H6z|M11 18h2",
  tv: "M3 6h18v12H3z|M8 21h8",
  speaker: "M7 3h10v18H7z|c:12,15,3|c:12,7,1",
  camera: "M3 8h4l2-3h6l2 3h4v11H3z|c:12,13,3.5",
  printer: "M7 8V3h10v5|M5 8h14v8H5z|M7 13h10v8H7z",
  server: "M4 4h16v6H4z|M4 14h16v6H4z|M8 7h.01|M8 17h.01",
  sensor: "M14 14.8V5a2 2 0 0 0-4 0v9.8a4 4 0 1 0 4 0z",
  plug: "M9 3v5|M15 3v5|M7 8h10v4a5 5 0 0 1-10 0z|M12 17v4",
  light: "M9 18h6|M10 21h4|M12 3a6 6 0 0 0-4 10.5c.8.8 1 1.5 1 2.5h6c0-1 .2-1.7 1-2.5A6 6 0 0 0 12 3z",
  car: "M3 12l2-5h14l2 5v6H3z|c:7,15,1|c:17,15,1",
  hub: "c:12,12,3|M12 3v3|M12 18v3|M3 12h3|M18 12h3",
  lock: "M5 11h14v10H5z|M8 11V7a4 4 0 0 1 8 0v4|M12 15v2",
  appliance: "M5 3h14v18H5z|M5 8h14|c:12,14.5,4|M8 5.5h.01|M11 5.5h.01",
  console: "M6 9h12a4 4 0 0 1 4 4v1a3 3 0 0 1-5 2l-1-1H8l-1 1a3 3 0 0 1-5-2v-1a4 4 0 0 1 4-4z|M8 12v2|M7 13h2",
  watch: "M8 6l1-3h6l1 3|M8 18l1 3h6l1-3|M7 6h10v12H7z",
  unknown: "c:12,12,9|M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7|M12 17h.01",
  alert: "M12 3l10 18H2z|M12 10v5|M12 18h.01",
  sparkle: "M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z",
  clock: "c:12,12,9|M12 7v5l3 2",
  list: "M8 6h12|M8 12h12|M8 18h12|M4 6h.01|M4 12h.01|M4 18h.01",
  x: "M6 6l12 12|M18 6L6 18",
  bell: "M6 16V11a6 6 0 0 1 12 0v5l2 2H4z|M10 21h4",
  gauge: "M4 18a8 8 0 1 1 16 0|M12 18l4-6|M12 18h.01",
  send: "M12 19V5|M5 12l7-7 7 7",
  star: "M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.5l6.1-.9z",
  door: "M6 21V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v17|M4 21h16|M14 12h.01",
  radiator: "M5 7v10|M9 7v10|M13 7v10|M17 7v10|M3 7h18|M3 17h18",
  dial: "M12 3c1 3.5 5.5 5.5 5.5 10.5a5.5 5.5 0 0 1-11 0c0-2.3 1-3.6 2.2-4.8.4 1.6 1.3 2.3 2 2.5C10.2 8.5 10.6 5.6 12 3z",
  siren: "M7 18v-6a5 5 0 0 1 10 0v6|M5 18h14|M12 3v2|M4.9 6.9l1.4 1.4|M19.1 6.9l-1.4 1.4",
  smoke: "c:12,12,9|c:12,12,4|M12 12h.01",
  cloud: "M7 18a4 4 0 0 1-.5-7.97A5.5 5.5 0 0 1 17 9a4.5 4.5 0 0 1 .5 9z",
  wind: "M3 8h11a3 3 0 1 0-3-3|M3 12h16a3 3 0 1 1-3 3|M3 16h8",
  drop: "M12 3s6 6.5 6 11a6 6 0 0 1-12 0c0-4.5 6-11 6-11z",
  leaf: "M5 19c0-8 5-13 14-14 0 9-5 14-13 14|M5 19c3-3 6-5 9-7",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z|c:12,12,3",
};
const NS = "http://www.w3.org/2000/svg";
function icon(name, size) {
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", "0 0 24 24"); s.setAttribute("class", "ic");
  if (size) { s.style.width = s.style.height = size + "px"; }
  for (const p of (ICONS[name] || ICONS.unknown).split("|")) {
    if (p.startsWith("c:")) {
      const [cx, cy, r] = p.slice(2).split(",");
      const c = document.createElementNS(NS, "circle");
      c.setAttribute("cx", cx); c.setAttribute("cy", cy); c.setAttribute("r", r); s.append(c);
    } else {
      const e = document.createElementNS(NS, "path"); e.setAttribute("d", p); s.append(e);
    }
  }
  return s;
}

// class -> [color, label, icon, zone]
const CLASS_STYLE = {
  router: ["#4aa3ff", "Router", "router", "infra"], access_point: ["#5ac8fa", "Access point", "router", "infra"],
  nas: ["#4dd0e1", "NAS", "server", "infra"], server: ["#4dd0e1", "Server", "server", "infra"], printer: ["#9ad1a0", "Printer", "printer", "infra"],
  computer: ["#b794f6", "Computer", "computer", "people"], phone: ["#f472b6", "Phone", "phone", "people"],
  tablet: ["#f472b6", "Tablet", "tablet", "people"], wearable: ["#f472b6", "Wearable", "watch", "people"],
  tv: ["#fbbf24", "TV", "tv", "media"], media: ["#fbbf24", "Media", "tv", "media"], speaker: ["#fcd34d", "Speaker", "speaker", "media"],
  game_console: ["#a3e635", "Console", "console", "media"],
  sensor: ["#3ee6b0", "Sensor", "sensor", "home"], plug: ["#3ee6b0", "Plug", "plug", "home"], light: ["#fde047", "Light", "light", "home"],
  thermostat: ["#3ee6b0", "Thermostat", "dial", "home"], hub: ["#3ee6b0", "Hub", "hub", "home"], iot: ["#3ee6b0", "IoT", "hub", "home"],
  lock: ["#f59e0b", "Smart lock", "lock", "home"], appliance: ["#38bdf8", "Appliance", "appliance", "home"],
  car: ["#cbd5e1", "Vehicle", "car", "home"], camera: ["#f87171", "Camera", "camera", "cams"],
  unknown: ["#7d8a9b", "Unknown", "unknown", "unknown"],
};
const ICON_COLOR = {
  router: "#4aa3ff", server: "#22d3ee", printer: "#94a3b8", computer: "#818cf8", phone: "#f472b6", tablet: "#d946ef", watch: "#94d2bd",
  tv: "#c084fc", speaker: "#fb923c", console: "#a3e635", sensor: "#2dd4bf", plug: "#facc15", light: "#fde68a", hub: "#34d399",
  lock: "#f59e0b", appliance: "#3b82f6", car: "#cbd5e1", camera: "#f87171", unknown: "#7d8a9b",
  dial: "#f97316", radiator: "#fb7185", door: "#fdba74", siren: "#e11d48", smoke: "#ea580c", cloud: "#7dd3fc", wind: "#a5b4fc", drop: "#67e8f9", leaf: "#86efac",
};
const iconColor = (n) => ICON_COLOR[n] || "#7d8a9b";
const ZONES = [["infra", "z_infra", "router"], ["people", "z_people", "computer"], ["media", "z_media", "tv"],
  ["home", "z_home", "hub"], ["cams", "z_cams", "camera"], ["unknown", "z_unknown", "unknown"]];
const CLASS_FR = { Router: "Routeur", "Access point": "Point d'accès", NAS: "NAS", Server: "Serveur", Printer: "Imprimante", Computer: "Ordinateur",
  Phone: "Téléphone", Tablet: "Tablette", Wearable: "Montre", TV: "TV", Media: "Média", Speaker: "Enceinte", Console: "Console", Sensor: "Capteur",
  Plug: "Prise", Light: "Lampe", Thermostat: "Thermostat", Hub: "Hub", IoT: "Objet connecté", Vehicle: "Véhicule", Camera: "Caméra",
  "Smart lock": "Serrure connectée", Appliance: "Électroménager", Unknown: "Inconnu" };
for (const v of Object.values(CLASS_STYLE)) v[0] = iconColor(v[2]);
const trCls = (l) => (LANG === "fr" ? (CLASS_FR[l] || l) : l);
const clsLabel = (c) => trCls(cs(c)[1]);
// radio device kind -> [icon, French label, English label]
const KINDS = {
  NACamDoorTag: ["door", "Capteur de porte", "Door sensor"], NIS: ["siren", "Sirène", "Siren"], NSD: ["smoke", "Détecteur de fumée", "Smoke alarm"],
  NCO: ["smoke", "Détecteur CO", "CO alarm"], NAMain: ["cloud", "Station météo", "Weather station"], NAModule1: ["sensor", "Module extérieur", "Outdoor module"],
  NAModule4: ["sensor", "Module intérieur", "Indoor module"], NAModule2: ["wind", "Anémomètre", "Anemometer"], NAModule3: ["drop", "Pluviomètre", "Rain gauge"],
  NHC: ["leaf", "Qualité de l'air", "Air quality"], NACamera: ["camera", "Caméra", "Camera"], NOC: ["camera", "Caméra", "Camera"], NDB: ["camera", "Sonnette", "Doorbell"],
  NATherm1: ["dial", "Thermostat", "Thermostat"], NRV: ["radiator", "Vanne radiateur", "Radiator valve"], NAPlug: ["hub", "Relais", "Relay"],
  VA: ["radiator", "Vanne radiateur", "Radiator valve"], RU: ["dial", "Thermostat", "Thermostat"], TR: ["dial", "Thermostat", "Thermostat"],
  SU: ["dial", "Thermostat", "Thermostat"], IB: ["hub", "Pont Internet", "Internet bridge"], BU: ["hub", "Pont Internet", "Internet bridge"],
};
const kindInfo = (r) => KINDS[r.kind] || KINDS[(r.kind || "").slice(0, 2)] || [cs(r.cls)[2], clsLabel(r.cls), clsLabel(r.cls)];
const kindLabel = (r) => kindInfo(r)[LANG === "fr" ? 1 : 2];
const SEV_COLOR = { critical: "var(--crit)", high: "var(--high)", medium: "var(--warn)", low: "var(--accent-2)", info: "var(--muted)" };
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

let token = "", devices = [], findings = [], openId = null, cfg = null;
const $ = (id) => document.getElementById(id);
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) n.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n;
}
async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.method && opts.method !== "GET" ? { "X-Kaa-Token": token } : {}) };
  const r = await fetch(path, { ...opts, headers });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
const name = (d) => d.label || d.hostname || d.vendor || d.mac;
const cs = (c) => CLASS_STYLE[c] || CLASS_STYLE.unknown;
const ago = (iso) => {
  if (!iso) return t("never");
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  return s < 60 ? t("just_now") : s < 3600 ? t("min_ago", { n: Math.floor(s / 60) }) : s < 86400 ? t("h_ago", { n: Math.floor(s / 3600) }) : t("d_ago", { n: Math.floor(s / 86400) });
};
const worst = (id) => findings.filter((f) => f.device_id === id && f.status === "open").sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity])[0];

/* ---------- theme ---------- */
const THEMES = ["dark", "light", "auto"];
let triageMap = {};
let cloudDevs = [];
function setTheme(mode) {
  document.documentElement.dataset.theme = mode;
  try { localStorage.setItem("kaa-theme", mode); } catch (e) { /* storage unavailable */ }
  $("theme").replaceChildren(icon(mode === "dark" ? "moon" : mode === "light" ? "sun" : "auto"));
  $("theme").dataset.tip = t("theme") + " : " + mode;
}
function initTheme() {
  let mode = "dark";
  try { mode = new URLSearchParams(location.search).get("theme") || localStorage.getItem("kaa-theme") || "dark"; } catch (e) { /* ignore */ }
  setTheme(THEMES.includes(mode) ? mode : "dark");
  $("theme").addEventListener("click", () => setTheme(THEMES[(THEMES.indexOf(document.documentElement.dataset.theme) + 1) % 3]));
}
const aiOn = () => !!(cfg && cfg.ai && cfg.ai.enabled);

/* ---------- overview ---------- */
const cov = { active: null, total: null, accepted: 0 };
function paintCover() {
  $("cover").textContent = [cov.total ? t("cover_checks", { a: cov.active, b: cov.total }) : "", cov.accepted ? t("cover_accepted", { n: cov.accepted }) : ""].filter(Boolean).join(" · ");
}
function renderOverview(o) {
  const v = o.score.value;
  $("score").textContent = v; $("grade").textContent = t("g_" + o.score.grade_id).toUpperCase();
  cov.accepted = o.score.accepted; paintCover();
  const ring = $("ring");
  ring.style.strokeDashoffset = 364.4 * (1 - v / 100);
  const col = v >= 90 ? "var(--ok)" : v >= 75 ? "var(--accent)" : v >= 50 ? "var(--warn)" : "var(--crit)";
  ring.style.stroke = col; ring.style.color = col;
  const rd = radioDevs();
  $("kline").textContent = t("online_of", { a: o.online + rd.filter((r) => r.reachable !== false).length, b: o.devices + rd.length }) + (o.unidentified ? " · " + t("unid_n", { n: o.unidentified }) : "");
  $("scope").textContent = (o.state.scope || []).join(", ") || t("scope_pending");
  const st = $("status");
  st.className = "status " + (o.state.running ? "running" : o.state.last_error ? "err" : "ok");
  $("status-text").textContent = o.state.running ? t("scanning") : o.state.last_error ? o.state.last_error : t("updated", { t: ago(o.state.last_run) });
  $("scan").disabled = $("deep").disabled = o.state.running;
  const h = o.history.map((p) => p.value), sp = $("spark");
  sp.replaceChildren();
  if (h.length > 1) {
    const lo = Math.min(...h), hi = Math.max(...h), span = Math.max(1, hi - lo);
    const pts = h.map((y, i) => `${(i / (h.length - 1)) * 240},${40 - ((y - lo) / span) * 34 - 2}`);
    const mk = (d, c) => { const p = document.createElementNS(NS, "path"); p.setAttribute("d", d); p.setAttribute("class", c); return p; };
    sp.append(mk("M" + pts.join(" L") + " L240,44 L0,44Z", "a"), mk("M" + pts.join(" L"), "l"));
    $("t-min").textContent = t("min") + " " + lo; $("t-max").textContent = t("max") + " " + hi;
    const d = h[h.length - 1] - h[0];
    $("t-delta").textContent = (d >= 0 ? "+" : "") + d + " " + t("over_scans", { n: h.length });
  } else { for (const i of ["t-min", "t-max", "t-delta"]) $(i).textContent = ""; $("t-delta").textContent = t("builds"); }
}
let digestHours = 24;
async function renderDigest() {
  const d = await api(`/api/digest?hours=${digestHours}`), box = $("digest");
  box.replaceChildren();
  const line = (k, v) => el("div", { class: "drow" }, el("span", {}, k), el("b", {}, String(v)));
  box.append(el("div", { class: "dh" }, el("span", {}, t(digestHours === 24 ? "last_24h" : "last_7d")),
    el("button", { class: "link", onclick: () => { digestHours = digestHours === 24 ? 168 : 24; renderDigest(); } }, t(digestHours === 24 ? "d_7d" : "d_24h"))),
  line(t("new_devices"), d.new_devices), line(t("went_offline"), d.went_offline),
  line(t("alerts_opened"), d.alerts_opened.length), line(t("alerts_resolved"), d.alerts_resolved.length));
}
function renderActions() {
  const box = $("actions"); box.replaceChildren();
  const open = findings.filter((f) => f.status === "open" && f.severity !== "info").sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]).slice(0, 5);
  box.closest("section").hidden = !open.length;
  if (!open.length) return;
  for (const f of open) {
    box.append(el("div", { class: `action sev-${f.severity}` },
      el("div", { class: "t" }, f.title), el("div", { class: "f" }, f.fix),
      el("div", { class: "row" }, el("span", { class: `badge ${f.severity}` }, t("sev_" + f.severity)),
        el("span", { class: "btns" },
          f.device_id ? el("button", { class: "link", onclick: () => openDrawer(f.device_id) }, t("view")) : null,
          el("button", { class: "link", onclick: () => ack(f.id) }, t("acknowledge"))))));
  }
}
async function ack(id, undo = false) { await api(`/api/findings/${id}/ack${undo ? "?undo=true" : ""}`, { method: "POST" }); await refresh(); }

/* ---------- AI analyst ---------- */
async function aiCall(path, body, box = $("ai")) {
  box.className = "ai dim"; box.textContent = t("analysing");
  try {
    const r = await api(path, { method: "POST", body: JSON.stringify(body || {}) });
    if (!r.enabled) box.textContent = t("ai_off");
    else if (r.error) { box.className = "ai err"; box.textContent = t("ai_error", { e: r.error }); }
    else { box.className = "ai"; box.textContent = (r.text || t("no_answer")).replace(/\*\*|^#+\s*/gm, ""); }
    return r;
  } catch (e) { box.className = "ai err"; box.textContent = t("cannot_reach_ai"); return null; }
}
const runBrief = () => aiCall("/api/ai/brief");
async function submitAsk(ev) {
  ev.preventDefault();
  const q = $("ask-q").value.trim();
  if (!q) return runBrief();
  await aiCall("/api/ai/ask", { question: q });
}

/* ---------- security checks (the threat watch lives here) ---------- */
function threatItem(it) {
  const v = triageMap[it.cve];
  return el("div", { class: "threat", style: v && v.relevant === "no" ? "opacity:.55" : null },
    el("div", {}, el("b", {}, `${it.vendor} ${it.product}`),
      it.match === "model" ? el("span", { class: "badge medium", style: "margin-left:8px" }, t("match_model")) : null,
      it.ransomware ? el("span", { class: "badge critical", style: "margin-left:8px" }, t("ransomware")) : null,
      v ? el("span", { class: `verdict ${v.relevant}` }, t("relevant_" + v.relevant)) : null),
    el("a", { href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(it.cve)}`, target: "_blank", rel: "noopener noreferrer" }, it.cve),
    el("div", { class: "m" }, `${it.name || it.summary} · ${it.added}${it.devices.length ? " · " + t("yours") + " : " + it.devices.join(", ") : ""}`),
    v && v.why ? el("div", { class: "why" }, v.why) : null);
}
async function renderHygiene() {
  const [r, th] = await Promise.all([api("/api/hygiene"), api("/api/threats").catch(() => null)]);
  const box = $("hygiene");
  cov.total = r.checks.length; cov.active = r.checks.filter((c) => c.status !== "na").length; paintCover();
  const look = { ok: ["check", "var(--ok)"], warn: ["alert", "var(--warn)"], ack: ["check", "var(--muted)"], na: ["minus", "var(--muted)"] };
  const enable = (key) => el("button", { class: "link", onclick: async () => { await setSetting({ [key]: true }); setTimeout(() => renderHygiene().catch(() => {}), 2500); } }, t("enable"));
  box.replaceChildren(...r.checks.map((c) => {
    const [gi, col] = look[c.status], suffix = { ok: "_o", warn: "_w", ack: "_w", na: "_n" }[c.status];
    const key = `hy_${c.id}${suffix}`;
    let detail = I18N.en[key] ? t(key, c.ev) + (c.status === "ack" ? " · " + t("hy_ack") : "") : "";
    const items = c.id === "kev" && th && th.enabled ? th.items : [];
    if (c.id === "kev" && c.status === "ok" && items.length) detail = t("hy_kev_v", { n: items.length });
    const extra = [];
    if (c.status === "na" && (c.id === "kev" || c.id === "exposure")) extra.push(enable(c.id === "kev" ? "threats" : "exposure"));
    if (items.length) {
      if (aiOn()) extra.push(el("button", { class: "link", onclick: runTriage }, t("triage")));
      extra.push(el("div", { class: "threats" }, ...items.slice(0, 6).map(threatItem)));
    }
    const tip = c.id === "kev" && th && th.catalog ? `${t("known_exploited", { n: th.catalog, t: ago(th.updated) })} · ${t("coverage", { n: th.coverage.devices, m: th.coverage.with_model, f: th.coverage.with_firmware })}` : null;
    return el("div", { class: "hy-row " + c.status, title: tip },
      el("span", { class: "hy-i", style: `color:${col}` }, icon(gi, 15)),
      el("div", { class: "hy-b" }, el("div", { class: "hy-t" }, t("hy_" + c.id)), detail ? el("div", { class: "hy-d" }, detail) : null, ...extra));
  }));
}
async function runTriage(ev) {
  const b = ev.currentTarget; b.classList.add("busy"); b.disabled = true;
  try {
    const r = await api("/api/ai/triage", { method: "POST", body: "{}" });
    triageMap = Object.fromEntries((r.items || []).filter((x) => ["yes", "maybe", "no"].includes(x.relevant)).map((x) => [x.cve, x]));
  } catch (e) { /* leave the list as it is */ }
  await renderHygiene();
}

/* ---------- internet ---------- */
const fmt = (v, u, d = 0) => (v == null ? "–" : `${Number(v).toFixed(d)} ${u}`);
function spark(vals, tip, w = 150, h = 34) {
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`); svg.setAttribute("class", "sp"); svg.setAttribute("preserveAspectRatio", "none");
  const pts = vals.map((v, i) => [i, v]).filter(([, v]) => v != null);
  if (pts.length < 2) return svg;
  const ys = pts.map(([, v]) => v), lo = Math.min(...ys), hi = Math.max(...ys), span = Math.max(hi - lo, hi * 0.1, 1);
  const xy = ([i, v]) => [2 + (i / (vals.length - 1)) * (w - 4), h - 3 - ((v - lo) / span) * (h - 8)];
  const mk = (tag, attrs) => { const n = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v); return n; };
  const line = pts.map((p, k) => (k ? "L" : "M") + xy(p).map((n) => n.toFixed(1)).join(","));
  svg.append(mk("path", { d: `${line.join(" ")} L${xy(pts[pts.length - 1])[0].toFixed(1)},${h} L${xy(pts[0])[0].toFixed(1)},${h}Z`, class: "a" }), mk("path", { d: line.join(" "), class: "l" }));
  for (const p of pts) {
    const [x, y] = xy(p), c = mk("circle", { cx: x.toFixed(1), cy: y.toFixed(1), r: 5 }), tt = document.createElementNS(NS, "title");
    tt.textContent = tip(p[0], p[1]); c.append(tt); svg.append(c);
  }
  return svg;
}
const median = (a) => { const s = [...a].sort((x, y) => x - y); return s.length ? s[Math.floor(s.length / 2)] : null; };
async function renderNet() {
  const n = await api("/api/internet"), box = $("net");
  const b = $("speed"); b.classList.toggle("busy", !!n.running); b.disabled = !!n.running;
  const L = n.last, H = n.history || [], lv = n.live || { series: [] };
  const when = (ts) => new Date(ts).toLocaleString(LANG, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
  const big = (v, u) => el("div", { class: "ni-v" }, v == null ? "–" : String(v), el("small", {}, u));
  const delta = (key) => {
    const vals = H.map((x) => x[key]).filter((v) => v != null), last = vals[vals.length - 1], med = median(vals.slice(0, -1));
    if (vals.length < 4 || !med) return null;
    const pct = Math.round(((last - med) / med) * 100);
    return el("span", { class: "ni-d " + (pct >= -10 ? "up" : "down") }, `${pct >= 0 ? "+" : ""}${pct} % ${t("n_usual")}`);
  };
  const metric = (key, label, unit) => el("div", { class: "ni-col" }, el("div", { class: "ni-k" }, label),
    n.running ? el("div", { class: "ni-run" }, icon("scan", 16), t("n_phase_" + (n.phase || "latency"))) : big(L ? Math.round(L[key]) : null, unit),
    n.running ? null : spark(H.map((x) => x[key]), (i, v) => `${Math.round(v)} ${unit} · ${when(H[i].ts)}`), n.running ? null : delta(key));
  const series = lv.series || [];
  const liveOn = series.length ? !!lv.up : null;
  const uses = L ? [["u_4k", L.down >= 25], ["u_calls", L.up >= 5 && L.latency < 100 && L.jitter < 30 && L.loss < 0.02],
    ["u_game", L.latency < 40 && L.jitter < 15 && L.loss === 0], ["u_backup", L.up >= 20]] : [];
  box.replaceChildren(el("div", { class: "ni" },
    el("div", { class: "ni-col" }, el("div", { class: "ni-k" }, el("i", { class: "ni-dot " + (liveOn === false ? "off" : liveOn ? "on" : "") }),
      liveOn === null ? "…" : liveOn ? t("n_online") : t("n_offline")),
    big(lv.ms == null ? null : Math.round(lv.ms), "ms"),
    spark(series.map((x) => x.ms), (i, v) => `${Math.round(v)} ms · ${when(series[i].ts)}`),
    el("div", { class: "ni-s" }, lv.avg != null ? `${t("n_avg")} ${Math.round(lv.avg)} ms` : "")),
    metric("down", t("net_down"), "Mb/s"), metric("up", t("net_up"), "Mb/s"),
    el("div", { class: "ni-col" }, el("div", { class: "ni-k" }, t("n_uses")),
      ...(uses.length ? uses.map(([k, ok]) => el("div", { class: "ni-u" + (ok ? "" : " no") }, el("span", { style: `color:${ok ? "var(--ok)" : "var(--warn)"}` }, icon(ok ? "check" : "alert", 14)), t(k)))
        : [el("div", { class: "ni-s" }, t("net_none"))]))),
  el("div", { class: "legend ni-f" }, [L ? t("n_last", { t: ago(L.ts) }) : t("n_never"),
    L ? `${t("net_jit")} ${fmt(L.jitter, "ms", 1)}` : "", L ? `${t("net_loss")} ${Math.round(L.loss * 100)} %` : "", `${t("net_outages")} : ${n.outages_7d}`].filter(Boolean).join(" · ")));
}
async function runSpeed() {
  const b = $("speed"); b.classList.add("busy"); b.disabled = true;
  try { await api("/api/speedtest", { method: "POST", body: "{}" }); } catch (e) { /* shown below */ }
  for (let i = 0; i < 45; i++) {
    await renderNet().catch(() => {});
    await new Promise((r) => setTimeout(r, 1500));
    const n = await api("/api/internet").catch(() => null);
    if (n && !n.running && i > 0) break;
  }
  await renderNet();
}

/* ---------- devices ---------- */
let chip = /^d\d+$/.test(location.hash.slice(1)) ? "all" : location.hash.slice(1) || "all";
const attn = (d) => { const w = worst(d.id); return !!w && w.severity !== "info"; };
function ipKey(ip) { return (ip || "").split(".").reduce((n, x) => n * 256 + Number(x || 0), 0); }
/* radio devices that are not already listed as a network device (same MAC, or the serial is in the hostname) */
function radioDevs() {
  const macs = new Set(devices.map((d) => (d.mac || "").toLowerCase()));
  const lan = devices.map((d) => [d.hostname, d.label].join(" ")).join("|").toLowerCase();
  return cloudDevs.filter((r) => { const id = String(r.ext_id).toLowerCase(); return !(macs.has(id) || (id.length >= 6 && lan.includes(id))); });
}
const grpOpen = new Map();
const srcName = (s) => ({ tado: "Tado", netatmo: "Netatmo" })[s] || s;
const BAD = "var(--crit)", LOW = "var(--warn)";
function radioState(r) {
  if (r.reachable === false) return [t("cl_unreachable"), BAD];
  if (r.battery === "low") return [t("cl_battery_low"), LOW];
  return [r.battery_pct != null ? `${r.battery_pct} %` : "OK", ""];
}
function radioRow(r, sub = false) {
  const [gi] = kindInfo(r), [st, sc] = radioState(r), off = r.reachable === false;
  return el("div", { class: "dev static" + (sub ? " sub" : "") + (off ? " off" : "") },
    el("i", { class: "live" + (off ? "" : " on") }), el("span", { class: "dg", style: `color:${iconColor(gi)}` }, icon(gi)),
    el("span", { class: "dn" }, r.name || r.kind), el("span", { class: "dt" }, kindLabel(r)),
    el("span", { class: "da", style: sc ? `color:${sc}` : null }, st),
    el("span", { class: "dv" }, [srcName(r.source), r.firmware ? `fw ${r.firmware}` : ""].filter(Boolean).join(" · ")), el("span", { class: "dc" }));
}
function groupRow(k, items, open) {
  const bad = items.filter((r) => r.reachable === false).length, low = items.filter((r) => r.battery === "low").length;
  const [st, sc] = bad ? [`${bad} ${t("cl_unreachable")}`, BAD] : low ? [`${low} ${t("cl_battery_low")}`, LOW] : ["OK", ""];
  const gi = kindInfo(items[0])[0];
  return el("button", { class: "dev grp" + (open ? " open" : ""), "aria-expanded": String(open), onclick: () => { grpOpen.set(k, !open); renderMap(); } },
    el("i", { class: "live" + (bad ? "" : " on") }), el("span", { class: "dg", style: `color:${iconColor(gi)}` }, icon(gi)),
    el("span", { class: "dn" }, k, el("span", { class: "cnt" }, `×${items.length}`)), el("span", { class: "dt" }),
    el("span", { class: "da", style: sc ? `color:${sc}` : null }, st),
    el("span", { class: "dv" }, [...new Set(items.map((r) => srcName(r.source)))].join(", ")), el("span", { class: "dc" }, "›"));
}
function renderMap() {
  const box = $("map"), q = $("q").value.trim().toLowerCase();
  const hit = (d) => !q || [name(d), d.ip, d.vendor, d.mac, clsLabel(d.class)].join(" ").toLowerCase().includes(q);
  const base = devices.filter(hit);
  const radio = radioDevs().filter((r) => !q || `${r.name} ${r.model} ${r.source}`.toLowerCase().includes(q));
  const count = (key) => base.filter((d) => cs(d.class)[3] === key).length;
  const tags = [["all", t("f_all"), base.length + radio.length],
    ...ZONES.map(([k, lbl]) => [k, t(lbl), count(k)]),
    ["radio", t("z_radio"), radio.length], ["attention", t("f_attention"), base.filter(attn).length]].filter(([k, , n]) => k === "all" || n > 0);
  if (!tags.some(([k]) => k === chip)) chip = "all";
  $("chips").replaceChildren(...tags.map(([k, lbl, n]) => el("button", { class: "tag" + (chip === k ? " on" : ""), onclick: () => { chip = k; renderMap(); } }, lbl, el("b", {}, String(n)))));

  const zoneIdx = (d) => ZONES.findIndex(([k]) => k === cs(d.class)[3]);
  const rows = base.filter((d) => chip === "all" || (chip === "attention" ? attn(d) : cs(d.class)[3] === chip))
    .sort((a, b) => Number(b.online) - Number(a.online) || zoneIdx(a) - zoneIdx(b) || ipKey(a.ip) - ipKey(b.ip));
  const nodes = rows.map((d) => {
    const [col, , gi] = cs(d.class), w = worst(d.id), isNew = w && w.rule_id === "KAA-NEW-DEVICE";
    return el("button", { class: "dev" + (d.online ? "" : " off") + (isNew ? " newdev" : ""), onclick: () => openDrawer(d.id),
      title: d.online ? name(d) : `${name(d)} · ${t("last_seen", { t: ago(d.last_seen) })}` },
    el("i", { class: "live" + (d.online ? " on" : "") }),
    el("span", { class: "dg", style: `color:${col}` }, icon(gi)),
    el("span", { class: "dn" }, name(d),
      d.critical === 1 ? el("span", { class: "flag", style: "color:var(--warn)", title: t("critical") }, icon("star", 12)) : null,
      attn(d) ? el("span", { class: "flag", style: `color:${SEV_COLOR[w.severity]}`, title: w.title }, icon("alert", 13)) : null),
    el("span", { class: "dt" }, clsLabel(d.class)), el("span", { class: "da" }, d.ip || "–"),
    el("span", { class: "dv" + (d.vendor ? "" : " dim") }, d.vendor || (d.randomized ? t("private_mac") : "")), el("span", { class: "dc" }, "›"));
  });
  if (chip === "all" || chip === "radio") {
    const byKind = new Map();
    for (const r of radio) { const k = kindLabel(r); if (!byKind.has(k)) byKind.set(k, []); byKind.get(k).push(r); }
    for (const [k, items] of [...byKind].sort((x, y) => x[0].localeCompare(y[0]))) {
      items.sort((x, y) => (x.name || "").localeCompare(y.name || ""));
      if (items.length < 3) { nodes.push(...items.map((r) => radioRow(r))); continue; }
      const open = q ? true : grpOpen.has(k) ? grpOpen.get(k) : chip === "radio";
      nodes.push(groupRow(k, items, open));
      if (open) nodes.push(...items.map((r) => radioRow(r, true)));
    }
  }
  box.replaceChildren(...(nodes.length ? nodes : [el("div", { class: "empty" }, t("no_match_dev"))]));
}

/* ---------- drawers ---------- */
function showDrawer(nodes) {
  const dr = $("drawer");
  dr.replaceChildren(el("button", { class: "close", onclick: closeDrawer, "aria-label": t("close") }, icon("x")), ...nodes.filter(Boolean));
  dr.classList.add("on"); $("scrim").classList.add("on"); dr.setAttribute("aria-hidden", "false");
  if (!opener) opener = document.activeElement;
  dr.querySelector(".close").focus();
}
let opener = null;
async function openDrawer(id) {
  openId = id;
  const d = await api(`/api/devices/${id}`), [col, , gi] = cs(d.class), label = clsLabel(d.class);
  const seg = el("div", { class: "seg" }, ...["unknown", "known", "guest"].map((k) =>
    el("button", { class: d.trust === k ? "on" : "", onclick: () => save(id, { trust: k }) }, t("tr_" + k))));
  const inp = el("input", { class: "input", value: d.label || "", placeholder: t("name_ph") });
  inp.addEventListener("change", () => save(id, { label: inp.value }));
  const crit = el("input", { type: "checkbox", class: "sw" }); crit.checked = d.critical === 1;
  crit.addEventListener("change", () => save(id, { critical: crit.checked }));
  const pres = await api(`/api/devices/${id}/presence`).catch(() => null);
  const kv = (pairs) => pairs.filter(([, v]) => v).flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)]);
  showDrawer([
    el("h3", {}, name(d)), el("div", { class: "sub" }, `${d.ip || t("no_address")} · ${d.mac}`),
    el("div", { class: "block" }, el("span", { class: "pill", style: `color:${col}` }, icon(gi), el("span", { style: "color:var(--text)" },
      label + (d.class !== "unknown" ? ` · ${Math.round(d.class_conf * 100)}% · ${d.class_source === "ai" ? t("by_ai") : t("by_rules")}` : "")))),
    el("div", { class: "block" }, el("h2", {}, t("name")), inp),
    el("div", { class: "block" }, el("div", { class: "set" }, el("div", { class: "lbl" }, t("critical"), el("small", {}, t("critical_hint"))), crit)),
    d.critical === 1 ? el("div", { class: "block" }, el("h2", {}, t("fw_title")),
      el("div", { class: "set" }, el("div", { class: "lbl" }, d.firmware_checked ? t("fw_last", { t: new Date(d.firmware_checked).toLocaleDateString(LANG) }) : t("fw_never"), el("small", {}, t("fw_hint"))),
        el("button", { class: "link", onclick: async () => { await api(`/api/devices/${id}/firmware-checked`, { method: "POST", body: "{}" }); await refresh(); await openDrawer(id); } }, t("fw_mark")))) : null,
    el("div", { class: "block" }, el("h2", {}, t("type")), typeGrid(d),
      el("div", { class: "sub", id: "learn-note", style: "margin-top:6px" }, d.class_source === "user" ? t("type_user_note") : t("type_auto_note"))),
    el("div", { class: "block" }, el("h2", {}, t("trust")), seg),
    presenceBlock(pres),
    el("div", { class: "block" }, el("h2", {}, t("issues")), ...(d.findings.length ? d.findings.map(findingCard) : [el("div", { class: "empty" }, t("none"))])),
    el("div", { class: "block" }, el("h2", {}, t("why", { x: label.toLowerCase() })),
      ...(d.class_evidence.length ? d.class_evidence.map(evidenceCard) : [el("div", { class: "empty" }, t("not_enough"))])),
    el("div", { class: "block" }, el("h2", {}, t("history")),
      ...(d.history.length ? d.history.slice(0, 12).map((e) => el("div", { class: "evidence" }, el("b", {}, ago(e.ts)), " · " + e.message)) : [el("div", { class: "empty" }, t("no_changes"))])),
    el("div", { class: "block" }, el("h2", {}, t("facts")), el("dl", { class: "kv" }, ...kv([
      [t("f_vendor"), d.vendor || (d.randomized ? t("private_addr") : t("unknown"))], [t("f_hostname"), d.hostname],
      [t("f_first"), ago(d.first_seen)], [t("f_last"), ago(d.last_seen)], ["mDNS", (d.facts.mdns_services || []).join(", ")],
      ["UPnP", d.facts.ssdp_server], [t("f_ports"), (d.facts.open_ports || []).join(", ")]]))),
  ]);
}
function presenceBlock(p) {
  if (!p || p.online_pct == null) return null;
  const hrs = p.cells.length, now = Date.now();
  const cell = (v, i) => {
    const at = new Date(now - (hrs - i) * 3600000).toLocaleString(LANG, { weekday: "short", hour: "2-digit", minute: "2-digit" });
    return el("i", { class: "pc" + (v === null ? " u" : ""), style: v === null ? null : `opacity:${(0.18 + 0.82 * v).toFixed(2)}`, title: v === null ? at : `${at} · ${Math.round(v * 100)} %` });
  };
  return el("div", { class: "block" }, el("h2", {}, t("presence"), el("span", { class: "pct" }, `${p.online_pct} % ${t("online_lc")}`)),
    el("div", { class: "pbar" }, ...p.cells.map(cell)));
}
function typeGrid(d) {
  const mk = (key, lbl, ic, col) => el("button", { class: "tag" + (d.class === key && d.class_source === "user" ? " on" : ""), onclick: () => setClass(d.id, key) },
    el("span", { style: col ? `color:${col};display:inline-flex` : "display:inline-flex" }, icon(ic, 14)), lbl);
  return el("div", { class: "chips" }, mk("auto", t("t_auto"), "scan"),
    ...Object.entries(CLASS_STYLE).filter(([k]) => k !== "unknown").map(([k, [col, lbl, ic]]) => mk(k, trCls(lbl), ic, col)));
}
async function setClass(id, cls) {
  const r = await api(`/api/devices/${id}`, { method: "PATCH", body: JSON.stringify({ device_class: cls }) });
  await refresh(); await openDrawer(id);
  const n = (r.applied_to || []).length;
  const note = $("learn-note");
  if (note && cls !== "auto") note.textContent = n ? t("type_saved_n", { n, l: r.applied_to.slice(0, 4).join(", ") }) : t("type_saved");
}
function findingCard(f) {
  const out = el("div", { class: "expl", hidden: true });
  const card = el("div", { class: `action sev-${f.severity}`, style: "cursor:default" },
    el("div", { class: "t" }, f.title), el("div", { class: "f" }, f.detail),
    el("div", { class: "f", style: "color:var(--text)" }, t("fix") + " : " + f.fix),
    el("div", { class: "row" }, el("span", { class: `badge ${f.severity}` }, t("sev_" + f.severity)),
      el("span", { style: "display:flex;gap:8px" },
        aiOn() ? el("button", { class: "link", onclick: async (e) => { e.target.disabled = true; out.hidden = false; await aiCall("/api/ai/explain", { finding_id: f.id }, out); e.target.disabled = false; } }, t("explain")) : null,
        el("button", { class: "link", onclick: async () => { await ack(f.id, f.status === "ack"); openDrawer(openId); } }, f.status === "ack" ? t("reopen") : t("acknowledge")))),
    out);
  return card;
}
function evidenceCard(e) {
  return el("div", { class: "evidence" }, el("b", {}, e.label), ` (${e.rule})`,
    el("div", { class: "bar-conf" }, el("i", { style: `width:${Math.round(e.confidence * 100)}%` })),
    el("div", {}, el("code", {}, JSON.stringify(e.matched))), e.reason ? el("div", {}, e.reason) : null);
}
async function save(id, patch) { await api(`/api/devices/${id}`, { method: "PATCH", body: JSON.stringify(patch) }); await refresh(); await openDrawer(id); }
function closeDrawer() {
  $("drawer").classList.remove("on"); $("scrim").classList.remove("on"); $("drawer").setAttribute("aria-hidden", "true"); openId = null;
  if (opener && document.contains(opener)) opener.focus();
  opener = null;
}

/* ---------- weekly report ---------- */

/* ---------- settings ---------- */
async function setSetting(patch) { cfg = await api("/api/settings", { method: "PUT", body: JSON.stringify(patch) }); }
async function setLang(lang) {
  await setSetting({ lang }); LANG = cfg.lang === "en" ? "en" : "fr";
  applyStatic(); paintHeader(); await refresh(); if ($("drawer").classList.contains("on")) closeDrawer();
}

function cloudBlock(cl) {
  const info = el("div", { class: "sub", style: "margin-top:6px" });
  const post = (path, body) => api(path, { method: body ? "PUT" : "POST", body: JSON.stringify(body || {}) });
  const off = (src) => el("button", { class: "link", onclick: async () => { await post(`/api/cloud/${src}/disconnect`); await refresh(); openSettings(); } }, t("cl_disconnect"));
  const tado = cl.tado.connected ? el("div", { class: "set" }, el("div", { class: "lbl" }, t("cl_tado"), el("small", {}, t("cl_connected"))), off("tado"))
    : el("div", { class: "set" }, el("div", { class: "lbl" }, t("cl_tado"), el("small", {}, t("cl_tado_help"))),
      el("button", { class: "link", onclick: async () => {
        try {
          const b = await post("/api/cloud/tado/begin");
          info.replaceChildren(el("a", { href: b.url, target: "_blank", rel: "noopener noreferrer" }, t("cl_open", { c: b.user_code })), el("div", {}, t("cl_waiting")));
          for (let i = 0; i < Math.ceil(b.expires_in / b.interval); i++) {
            await new Promise((r) => setTimeout(r, b.interval * 1000));
            const p = await post("/api/cloud/tado/poll");
            if (p.status === "connected") { await refresh(); return openSettings(); }
            if (p.status === "failed") { info.textContent = t("cl_failed", { e: p.error || "" }); return; }
          }
        } catch (e) { info.textContent = t("cl_failed", { e: e.message }); }
      } }, t("cl_connect")));
  const id = el("input", { class: "input", placeholder: t("cl_id"), autocomplete: "off" });
  const secret = el("input", { class: "input", type: "password", placeholder: t("cl_secret"), autocomplete: "off" });
  const netatmo = cl.netatmo.connected ? el("div", { class: "set" }, el("div", { class: "lbl" }, t("cl_netatmo"), el("small", {}, t("cl_connected"))), off("netatmo"))
    : el("div", {}, el("div", { class: "set" }, el("div", { class: "lbl" }, t("cl_netatmo"), el("small", {}, t("cl_netatmo_help")))),
      cl.netatmo.configured ? el("button", { class: "link", onclick: async () => {
        try { const r = await api("/api/cloud/netatmo/start", { method: "POST", body: "{}" }); window.open(r.url, "_blank", "noopener"); } catch (e) { info.textContent = t("cl_failed", { e: e.message }); }
      } }, t("cl_authorize")) : null,
      el("div", { style: "display:grid;gap:6px;margin-top:8px" }, id, secret,
        el("button", { class: "link", onclick: async () => {
          if (!id.value.trim() || !secret.value.trim()) return;
          try { await post("/api/cloud/netatmo/config", { client_id: id.value, client_secret: secret.value }); info.textContent = t("cl_saved"); openSettings(); } catch (e) { info.textContent = t("cl_failed", { e: e.message }); }
        } }, t("cl_save"))));
  return el("div", { class: "block" }, el("h2", {}, t("s_cloud")), tado, netatmo, info);
}
async function openSettings() {
  cfg = await api("/api/settings");
  const cl = await api("/api/cloud").catch(() => ({ tado: {}, netatmo: {} }));
  const row = (label, hint, control) => el("div", { class: "set" }, el("div", { class: "lbl" }, label, hint ? el("small", {}, hint) : null), control);
  const sw = (key) => { const i = el("input", { type: "checkbox", class: "sw" }); i.checked = !!cfg[key]; i.addEventListener("change", () => setSetting({ [key]: i.checked })); return i; };
  const time = (key) => { const i = el("input", { type: "time", class: "time", value: cfg[key] }); i.addEventListener("change", () => i.value && setSetting({ [key]: i.value })); return i; };
  const interval = el("select", { class: "select" }, ...[[300, "m5"], [900, "m15"], [1800, "m30"], [3600, "h1"]].map(([v, l]) => el("option", { value: v, selected: cfg.interval === v }, t(l))));
  interval.addEventListener("change", () => setSetting({ interval: Number(interval.value) }));
  const digest = el("select", { class: "select" }, el("option", { value: -1, selected: cfg.digest_hour === -1 }, t("off")),
    ...[6, 7, 8, 9, 10].map((h) => el("option", { value: h, selected: cfg.digest_hour === h }, `${h}:00`)));
  digest.addEventListener("change", () => setSetting({ digest_hour: Number(digest.value) }));
  const kw = el("input", { class: "input", value: (cfg.threat_keywords || []).join(", "), placeholder: "eero, tado" });
  kw.addEventListener("change", () => setSetting({ threat_keywords: kw.value.split(",").map((x) => x.trim()).filter(Boolean) }));
  showDrawer([
    el("h3", {}, t("settings")), el("div", { class: "sub" }, t("settings_sub")),
    el("div", { class: "block" }, el("h2", {}, t("s_alerts")),
      row(t("s_notify"), t("s_notify_h"), sw("notify")),
      row(t("s_quiet"), t("s_quiet_h"), time("quiet_start")),
      row(t("s_wake_wd"), "", time("wake_weekday")), row(t("s_wake_we"), "", time("wake_weekend")),
      row(t("s_digest"), t("s_digest_h"), digest)),
    el("div", { class: "block" }, el("h2", {}, t("s_scanning")),
      row(t("s_every"), t("s_every_h"), interval),
      row(t("s_ports"), t("s_ports_h"), sw("portscan"))),
    el("div", { class: "block" }, el("h2", {}, t("s_threats")),
      row(t("s_cisa"), t("s_cisa_h"), sw("threats")), row(t("s_kw"), "", kw),
      row(t("s_exposure"), t("s_exposure_h"), sw("exposure"))),
    el("div", { class: "block" }, el("h2", {}, t("s_ai")),
      el("div", { class: "evidence" }, cfg.ai.enabled ? t("ai_on", { m: cfg.ai.model || "model" }) : t("ai_off_s"))),
    cloudBlock(cl),
  ]);
}

/* ---------- loop ---------- */
async function refresh() {
  const [o, d, f, c] = await Promise.all([api("/api/overview"), api("/api/devices"), api("/api/findings"), api("/api/cloud").catch(() => ({ devices: [] }))]);
  devices = d; findings = f; cloudDevs = c.devices || [];
  renderOverview(o); renderActions(); renderMap();
  renderDigest().catch(() => {}); renderHygiene().catch(() => {}); renderNet().catch(() => {});
}
let scanning = false;
async function startScan(ports) {
  if (scanning) return;
  scanning = true;  // instant feedback: do not wait for the next poll
  $("scan").disabled = $("deep").disabled = true;
  (ports ? $("deep") : $("scan")).classList.add("busy");
  $("status").className = "status running"; $("status-text").textContent = ports ? t("deep") : t("scanning");
  try { await api("/api/scan", { method: "POST", body: JSON.stringify({ ports }) }); } catch (e) { /* shown by refresh */ }
  for (let i = 0; i < 60; i++) {  // poll until the cycle is over (max about 90 s)
    await new Promise((r) => setTimeout(r, 1500));
    const o = await api("/api/overview").catch(() => null);
    if (o && !o.state.running && i > 0) break;
  }
  scanning = false;
  $("scan").classList.remove("busy"); $("deep").classList.remove("busy");
  await refresh();
}

const ic = (id, name) => $(id).replaceChildren(icon(name));
const tx = (id, key) => { $(id).textContent = t(key); };
function paintHeader() {
  ic("scan", "scan"); ic("deep", "radar"); ic("settings", "gear"); ic("ask-go", "send");
  tx("brief", "ai_brief_btn"); tx("speed", "net_btn");
  $("lang").textContent = LANG.toUpperCase();
  if (!aiOn()) { $("ai").className = "ai dim"; $("ai").textContent = t("ai_off"); }
}

async function boot() {
  if (new URLSearchParams(location.search).has("still")) document.documentElement.classList.add("still");
  initTheme();
  try { cfg = await api("/api/settings"); LANG = cfg.lang === "en" ? "en" : "fr"; } catch (e) { /* default fr */ }
  applyStatic(); paintHeader();
  const sess = await api("/api/session");
  token = sess.token;
  $("foot").textContent = `© ${new Date().getFullYear()} Kaa contributors · MIT License · v${sess.version}`;
  $("scan").addEventListener("click", () => startScan(false));
  $("deep").addEventListener("click", () => startScan(true));
  $("settings").addEventListener("click", openSettings);
  $("lang").addEventListener("click", () => setLang(LANG === "fr" ? "en" : "fr"));
  $("brief").addEventListener("click", runBrief);
  $("speed").addEventListener("click", runSpeed);
  $("ask").addEventListener("submit", submitAsk);
  $("q").addEventListener("input", renderMap);
  $("scrim").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  await refresh();
  const open = /^d(\d+)$/.exec(location.hash.slice(1)); if (open) openDrawer(Number(open[1]));
  setInterval(() => { if (!document.hidden) refresh().catch(() => {}); }, 8000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh().catch(() => {}); });
}
boot().catch((e) => { $("status-text").textContent = t("unreachable", { e: e.message }); });

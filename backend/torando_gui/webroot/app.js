// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
"use strict";

const TOKEN = document.querySelector('meta[name="torando-token"]').getAttribute("content");
const MAP = window.TORANDO_MAP || { w: 1000, h: 500, land: "", points: {}, names: {} };
const ZOOM = 4.6; // fly-in scale for a country-centroid (no precise coords)
const CITY_ZOOM = 6.6; // tighter fly-in when we have the exit's real lat/lon
const CHIP_CCS = ["se", "us", "de", "nl", "ch", "gb", "fr", "ca", "jp"];

async function api(path, opts = {}) {
  const headers = { "X-Torando-Token": TOKEN };
  let body;
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  const res = await fetch(path, { method: opts.method || "GET", headers, body });
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

const el = (id) => document.getElementById(id);
const body = document.body;
const dom = {
  mockBanner: el("mock-banner"),
  userBtn: el("user-btn"), userLabel: el("user-label"), userPop: el("user-pop"),
  openSettings: el("open-settings"), closeSettings: el("close-settings"),
  overlay: el("overlay"), drawer: el("drawer"),
  mapLand: el("map-land"), mapZoom: el("map-zoom"), marker: el("marker"),
  status: document.querySelector(".status"), statusToggle: el("status-toggle"),
  statusTag: el("status-tag"), statusState: el("status-state"), statusWhere: el("status-where"),
  statusDetail: el("status-detail"),
  statusProgress: el("status-progress"), statusProgressBar: el("status-progress-bar"),
  dExit: el("d-exit"), dCountry: el("d-country"), dCity: el("d-city"), dCoords: el("d-coords"),
  dDns: el("d-dns"), dTor: el("d-tor"), dCircuits: el("d-circuits"),
  console: el("console"), clearLog: el("clear-log"),
  switchLocation: el("switch-location"), locValue: el("loc-value"),
  action: el("action"), actionLabel: el("action-label"), newnym: el("newnym"),
  form: el("settings-form"), settingsMsg: el("settings-msg"), countryChips: el("country-chips"),
};

let lastStatus = null;
let lastExit = null;   // {is_tor, ip, error, country, lat, lon, city}
let users = [];
let busy = false;
let bootTimer = null;

function countryName(cc) {
  if (!cc) return null;
  return MAP.names[cc] || cc.toUpperCase();
}

// ---------- state ----------
function deriveState(s) {
  if (!s) return "unknown";
  const boot = s.control && s.control.bootstrap;
  const progress = boot ? boot.progress : s.active ? 100 : 0;
  if (s.active) {
    const dnsLeak = !s.dns.via_tor;
    const exitLeak = lastExit && lastExit.is_tor === false;
    if (dnsLeak || exitLeak) return "leak";
    if (progress < 100 && boot) return "bootstrapping";
    return "routed";
  }
  if (boot && progress > 0 && progress < 100) return "bootstrapping";
  return "direct";
}

const TAG = { unknown: "checking", direct: "unsecured", bootstrapping: "connecting", routed: "secured", leak: "leaking" };

function render(s) {
  lastStatus = s;
  const state = deriveState(s);
  body.dataset.state = state;
  const boot = s.control && s.control.bootstrap;
  const progress = boot ? boot.progress : s.active ? 100 : 0;

  dom.statusTag.textContent = TAG[state];

  const HERO = {
    unknown: "Checking system\u2026",
    direct: "Unsecured connection",
    bootstrapping: "Creating connection\u2026",
    routed: "Secure connection",
    leak: "Connection unsafe",
  };
  dom.statusState.textContent = HERO[state];

  if (state === "unknown") {
    dom.statusWhere.innerHTML = "&nbsp;";
  } else if (state === "direct") {
    dom.statusWhere.textContent = "Your traffic is not going through Tor";
  } else if (state === "bootstrapping") {
    dom.statusWhere.textContent = `Bootstrapping Tor \u2014 ${progress}%`;
  } else if (state === "routed") {
    const ip = lastExit && lastExit.ip;
    if (ip) dom.statusWhere.innerHTML = `${exitPlace()} &middot; <span class="mono">${ip}</span>`;
    else dom.statusWhere.textContent = "Routed through Tor";
  } else if (state === "leak") {
    if (!s.dns.via_tor) dom.statusWhere.textContent = "DNS is not pinned to 127.0.0.1";
    else if (lastExit && lastExit.is_tor === false) dom.statusWhere.textContent = "Exit IP is not a Tor node";
    else dom.statusWhere.textContent = "A check did not pass";
  }

  // connecting progress bar (driven by the real bootstrap %)
  const showProg = state === "bootstrapping";
  dom.statusProgress.hidden = !showProg;
  if (showProg) dom.statusProgressBar.style.width = `${progress}%`;

  // action button
  const off = state === "unknown" || state === "direct";
  dom.actionLabel.textContent = off
    ? "Secure my connection"
    : state === "bootstrapping" ? "Cancel" : "Disconnect";
  dom.action.classList.toggle("is-on", !off);
  dom.action.disabled = busy || state === "unknown";
  dom.newnym.hidden = state !== "routed";

  // location switcher reflects the pinned exit country (the relay analog)
  const pin = s.config && s.config.exit_country;
  dom.locValue.textContent = pin ? countryName(pin) : "Automatic";
  syncChips(pin);

  // user label
  if (s.target_uid != null) {
    const u = users.find((x) => x.uid === s.target_uid);
    dom.userLabel.textContent = u ? u.name : `uid ${s.target_uid}`;
  } else {
    dom.userLabel.textContent = "no user";
  }

  // detail panel
  dom.dExit.textContent = (lastExit && lastExit.ip) || "\u2014";
  dom.dCountry.textContent = (lastExit && lastExit.country) ? countryName(lastExit.country) : "\u2014";
  dom.dCity.textContent = (lastExit && lastExit.city) || "\u2014";
  dom.dCoords.textContent =
    lastExit && lastExit.lat != null && lastExit.lon != null
      ? `${Number(lastExit.lat).toFixed(4)}, ${Number(lastExit.lon).toFixed(4)}`
      : "\u2014";
  dom.dDns.textContent = s.dns.nameserver || "\u2014";
  const tor = s.tor || {};
  dom.dTor.textContent = tor.active === true ? "running" : tor.active === false ? (tor.installed ? "stopped" : "absent") : "unknown";
  dom.dCircuits.textContent = String((s.control && s.control.circuits) || 0);

  dom.mockBanner.hidden = !s.mock;
  if (!dom.drawer.classList.contains("open")) fillForm(s.config);

  flyTo(mapTarget(state, s));
  scheduleBootPoll(state);

  // if we just became active but have no exit reading yet, fetch one
  if (s.active && !lastExit) refreshExit();
}

// while bootstrapping, poll faster than the 2s SSE so the bar animates
function scheduleBootPoll(state) {
  if (state === "bootstrapping" && !bootTimer) {
    bootTimer = setInterval(async () => {
      try { render(await api("/api/status")); } catch { /* transient */ }
    }, 600);
  } else if (state !== "bootstrapping" && bootTimer) {
    clearInterval(bootTimer);
    bootTimer = null;
  }
}

// equirectangular projection matching packaging/geo/gen_worldmap.py
function projectLatLon(lat, lon) {
  const x = ((Number(lon) + 180) / 360) * MAP.w;
  const y = ((90 - Number(lat)) / 180) * MAP.h;
  return [x, y];
}

// "Göteborg, Sweden" | "Sweden" | "Tor exit"
function exitPlace() {
  const country = countryName(lastExit && lastExit.country);
  const city = lastExit && lastExit.city;
  if (city && country) return `${city}, ${country}`;
  return city || country || "Tor exit";
}

// focus target: real exit coordinates first, then country centroid; null = world
function mapTarget(state, s) {
  if (state !== "routed" && state !== "bootstrapping") return null;
  if (lastExit && lastExit.lat != null && lastExit.lon != null) {
    const [x, y] = projectLatLon(lastExit.lat, lastExit.lon);
    return { x, y, precise: true };
  }
  const cc = (lastExit && lastExit.country) || (s.config && s.config.exit_country);
  const pt = cc && MAP.points[cc];
  return pt ? { x: pt[0], y: pt[1], precise: false } : null;
}

function flyTo(target) {
  if (!target) {
    dom.marker.setAttribute("opacity", "0");
    dom.mapZoom.setAttribute("transform", "translate(0 0) scale(1)");
    return;
  }
  const { x, y, precise } = target;
  dom.marker.setAttribute("transform", `translate(${x} ${y})`);
  dom.marker.setAttribute("opacity", "1");
  const z = precise ? CITY_ZOOM : ZOOM;
  const tx = MAP.w / 2 - z * x;
  const ty = MAP.h / 2 - z * y;
  dom.mapZoom.setAttribute("transform", `translate(${tx} ${ty}) scale(${z})`);
}

// ---------- exit check ----------
async function refreshExit() {
  try {
    const info = await api("/api/exit");
    lastExit = info;
  } catch (e) {
    lastExit = { is_tor: null, ip: null, error: e.message, country: null, lat: null, lon: null, city: null };
  }
  if (lastStatus) render(lastStatus);
}

// ---------- actions ----------
async function withBusy(fn) {
  if (busy) return;
  busy = true; dom.action.disabled = true;
  try { await fn(); } catch (e) { logLine({ level: "error", msg: e.message }); }
  finally { busy = false; dom.action.disabled = false; }
}

async function toggleAction() {
  const s = lastStatus;
  const on = s && s.active;
  if (!on && (!s || s.target_uid == null)) {
    logLine({ level: "warn", msg: "select a user before connecting" });
    openUserPop();
    return;
  }
  await withBusy(async () => {
    const res = await api(on ? "/api/disconnect" : "/api/connect", { method: "POST" });
    if (!res.active) lastExit = null;
    render(res);
    if (res.active) refreshExit();
  });
}

async function newIdentity() {
  try {
    await api("/api/newnym", { method: "POST" });
    logLine({ level: "info", msg: "requested a new Tor identity" });
    if (lastStatus && lastStatus.active) setTimeout(refreshExit, 1500);
  } catch (e) { logLine({ level: "error", msg: e.message }); }
}

async function setConfig(patch, msgEl) {
  if (msgEl) msgEl.textContent = "saving\u2026";
  try {
    const s = await api("/api/config", { method: "POST", body: patch });
    render(s);
    if (msgEl) msgEl.textContent = "saved";
    return true;
  } catch (e) {
    if (msgEl) msgEl.textContent = e.message; else logLine({ level: "error", msg: e.message });
    return false;
  }
}

// ---------- user popover ----------
function buildUserPop() {
  dom.userPop.innerHTML = "";
  if (!users.length) {
    const d = document.createElement("div");
    d.className = "pop-empty";
    d.textContent = "no eligible users";
    dom.userPop.appendChild(d);
    return;
  }
  for (const u of users) {
    const b = document.createElement("button");
    b.type = "button";
    b.setAttribute("role", "menuitemradio");
    b.textContent = `${u.name} (uid ${u.uid})`;
    const chosen = lastStatus && lastStatus.target_uid === u.uid;
    b.setAttribute("aria-checked", chosen ? "true" : "false");
    b.addEventListener("click", async () => {
      closeUserPop();
      await setConfig({ target_uid: u.uid });
    });
    dom.userPop.appendChild(b);
  }
}
function openUserPop() {
  buildUserPop();
  dom.userPop.hidden = false;
  dom.userBtn.setAttribute("aria-expanded", "true");
}
function closeUserPop() {
  dom.userPop.hidden = true;
  dom.userBtn.setAttribute("aria-expanded", "false");
}

// ---------- country chips ----------
function buildChips() {
  dom.countryChips.innerHTML = "";
  const mk = (cc, label) => {
    const b = document.createElement("button");
    b.type = "button"; b.dataset.cc = cc; b.textContent = label;
    b.addEventListener("click", () => {
      const cur = lastStatus && lastStatus.config && lastStatus.config.exit_country;
      const next = cur === cc ? "" : cc; // toggle off if already selected
      setConfig({ exit_country: next }, dom.settingsMsg);
    });
    dom.countryChips.appendChild(b);
  };
  mk("", "Automatic");
  for (const cc of CHIP_CCS) mk(cc, countryName(cc));
}
function syncChips(pin) {
  for (const b of dom.countryChips.querySelectorAll("button")) {
    const cc = b.dataset.cc;
    b.classList.toggle("sel", (cc || "") === (pin || ""));
  }
}

// ---------- settings form ----------
const NUM = ["trans_port", "dns_port", "socks_port", "control_port"];
const BOOL = ["manage_torrc", "enable_control_port", "lock_resolv", "use_bridges"];

function fillForm(cfg) {
  if (!cfg) return;
  for (const f of NUM) {
    const i = dom.form.elements[f];
    if (i && document.activeElement !== i) i.value = cfg[f];
  }
  for (const f of BOOL) { const i = dom.form.elements[f]; if (i) i.checked = !!cfg[f]; }
  const ec = dom.form.elements["exit_country"];
  if (ec && document.activeElement !== ec) ec.value = cfg.exit_country || "";
  const br = dom.form.elements["bridges"];
  if (br && document.activeElement !== br) br.value = (cfg.bridges || []).join("\n");
}
function readForm() {
  const p = {};
  for (const f of NUM) { const v = parseInt(dom.form.elements[f].value, 10); if (Number.isFinite(v)) p[f] = v; }
  for (const f of BOOL) p[f] = dom.form.elements[f].checked;
  p.exit_country = dom.form.elements["exit_country"].value.trim().toLowerCase();
  p.bridges = dom.form.elements["bridges"].value.split("\n").map((x) => x.trim()).filter(Boolean);
  return p;
}

function openDrawer(focusExit) {
  if (lastStatus) fillForm(lastStatus.config);
  dom.drawer.classList.add("open");
  dom.overlay.hidden = false;
  dom.drawer.setAttribute("aria-hidden", "false");
  const target = focusExit ? dom.form.elements["exit_country"] : dom.form.querySelector("input,textarea");
  if (target) target.focus();
}
function closeDrawer() {
  dom.drawer.classList.remove("open");
  dom.overlay.hidden = true;
  dom.drawer.setAttribute("aria-hidden", "true");
  dom.settingsMsg.textContent = "";
}

// ---------- console ----------
function logLine(rec) {
  const li = document.createElement("li");
  li.className = rec.level || "info";
  const t = new Date((rec.ts || Date.now() / 1000) * 1000);
  const hms = [t.getHours(), t.getMinutes(), t.getSeconds()].map((n) => String(n).padStart(2, "0")).join(":");
  const time = document.createElement("time"); time.textContent = hms;
  const lvl = document.createElement("span"); lvl.className = "lvl"; lvl.textContent = (rec.level || "info").toUpperCase();
  const msg = document.createElement("span"); msg.className = "msg"; msg.textContent = rec.msg || "";
  li.append(time, lvl, msg);
  const atBottom = dom.console.scrollTop + dom.console.clientHeight >= dom.console.scrollHeight - 8;
  dom.console.appendChild(li);
  while (dom.console.childElementCount > 400) dom.console.removeChild(dom.console.firstChild);
  if (atBottom) dom.console.scrollTop = dom.console.scrollHeight;
}

// ---------- SSE ----------
function connectEvents() {
  const src = new EventSource(`/api/events?token=${encodeURIComponent(TOKEN)}`);
  src.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.type === "log") logLine(m);
    else if (m.type === "status") render(m.data);
  };
  src.onerror = () => {};
}

// ---------- boot ----------
async function boot() {
  if (MAP.land) dom.mapLand.setAttribute("d", MAP.land);
  buildChips();

  dom.action.addEventListener("click", toggleAction);
  dom.newnym.addEventListener("click", newIdentity);
  dom.statusToggle.addEventListener("click", () => {
    const open = dom.status.classList.toggle("open");
    dom.statusDetail.hidden = !open;
    dom.statusToggle.setAttribute("aria-expanded", open ? "true" : "false");
  });
  dom.clearLog.addEventListener("click", () => (dom.console.innerHTML = ""));
  dom.switchLocation.addEventListener("click", () => openDrawer(true));
  dom.openSettings.addEventListener("click", () => openDrawer(false));
  dom.closeSettings.addEventListener("click", closeDrawer);
  dom.overlay.addEventListener("click", closeDrawer);
  dom.form.addEventListener("submit", (e) => { e.preventDefault(); setConfig(readForm(), dom.settingsMsg).then((ok) => { if (ok) setTimeout(closeDrawer, 500); }); });

  dom.userBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    dom.userPop.hidden ? openUserPop() : closeUserPop();
  });
  document.addEventListener("click", (e) => {
    if (!dom.userPop.hidden && !dom.userPop.contains(e.target) && e.target !== dom.userBtn) closeUserPop();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (dom.drawer.classList.contains("open")) closeDrawer();
    else if (!dom.userPop.hidden) closeUserPop();
  });

  try {
    const [u, s] = await Promise.all([api("/api/users"), api("/api/status")]);
    users = u;
    render(s);
    if (s.active) refreshExit();
  } catch (e) {
    logLine({ level: "error", msg: `init: ${e.message}` });
  }
  connectEvents();
}

boot();

// ═══════════════════════════════════════════════════════════════════════
// netviz – live network flow visualizer (frontend)
//
// 1. Fetches runtime configuration from /api/config (basemap key, view).
// 2. Initializes the Leaflet map with the fetched tile provider.
// 3. Opens a WebSocket to /ws and renders live flows, connections and
//    markers on top of the map.
// 4. Provides a live filter box over the connections list.
// ═══════════════════════════════════════════════════════════════════════

// ─── Runtime configuration (populated from /api/config) ───────────────
let CONFIG = null;

/**
 * Fetch runtime configuration from the backend.
 * Everything that used to be hard-coded (basemap URL, API key, default
 * view) now comes from `backend/config.py` via this endpoint.
 */
async function loadConfig() {
  const res = await fetch('/api/config');
  if (!res.ok) throw new Error(`config fetch failed: ${res.status}`);
  CONFIG = await res.json();
}

// ─── Constants ────────────────────────────────────────────────────────
const COLOR_BY_PROTO = {
  1:  '#f59e0b',   // ICMP
  6:  '#22c55e',   // TCP
  17: '#3b82f6',   // UDP
};
const PROTO_NAME      = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' };
const DEFAULT_COLOR   = '#94a3b8';
const HIGHLIGHT_COLOR = '#ef4444';
const LAN_JITTER_DEG  = 0.08;

// ─── State ────────────────────────────────────────────────────────────
const flows       = new Map();   // key → { layer, arrow, flow, highlighted }
const ipRefs      = new Map();   // "role:ip" → Set<flowKey>
const ipMarkers   = new Map();   // "role:ip" → { marker, lastHostname, lastExternal }
const connections = new Map();   // "src|dst" → connection row state

let highlightedConn = null;      // currently highlighted connection key
let highlightGhost  = null;      // temporary layers for expired connections
let ws              = null;
let map             = null;

// Current filter string (lower-cased). Empty string = no filtering.
let filterQuery = '';

// ─── DOM handles ──────────────────────────────────────────────────────
const elFlows       = document.getElementById('stat-flows');
const elIPs         = document.getElementById('stat-ips');
const elStatus      = document.getElementById('stat-status');
const elExtIp       = document.getElementById('stat-extip');
const elConnList    = document.getElementById('conn-list');
const elConnCount   = document.getElementById('conn-count');
const elConnHeader  = document.getElementById('conn-header');
const elConnBox     = document.getElementById('connections');
const elSelectAll   = document.getElementById('select-all');
const elSearch      = document.getElementById('conn-search');
const elSearchClear = document.getElementById('conn-search-clear');
const elConnEmpty   = document.getElementById('conn-empty');

// ═══════════════════════════════════════════════════════════════════════
// Small helpers
// ═══════════════════════════════════════════════════════════════════════

/** Join a flow key array into a string. */
function keyStr(k) { return k.join('|'); }

/** Build the connection key from src/dst IPs. */
function connKeyStr(srcIp, dstIp) { return `${srcIp}|${dstIp}`; }

/**
 * Deterministic small offset for LAN markers so that multiple devices
 * do not overlap. Uses a stable hash of the IP.
 */
function hashOffset(ip) {
  let h = 0;
  for (let i = 0; i < ip.length; i++) {
    h = (h * 31 + ip.charCodeAt(i)) | 0;
  }
  const angle = (Math.abs(h) % 360) * Math.PI / 180;
  return [Math.sin(angle) * LAN_JITTER_DEG, Math.cos(angle) * LAN_JITTER_DEG];
}

/** Compute map coordinates for a geo object (with LAN jitter). */
function coordsFor(geo) {
  if (geo.is_local) {
    const [dLat, dLon] = hashOffset(geo.ip);
    return [geo.lat + dLat, geo.lon + dLon];
  }
  return [geo.lat, geo.lon];
}

/** Escape user-controlled strings before injecting into innerHTML. */
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function protoColor(proto) { return COLOR_BY_PROTO[proto] || DEFAULT_COLOR; }
function hasValidGeo(geo)  {
  return geo && typeof geo.lat === 'number' && typeof geo.lon === 'number';
}

// ═══════════════════════════════════════════════════════════════════════
// Map initialization
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build the Leaflet map using the settings fetched from /api/config.
 * Must be called AFTER `loadConfig()` has resolved.
 */
function initMap() {
  const { basemap, map: view } = CONFIG;

  map = L.map('map', { worldCopyJump: true })
        .setView([view.defaultLat, view.defaultLon], view.defaultZoom);

  const url = basemap.urlTemplate.replace('{key}', basemap.apiKey);

  L.tileLayer(url, {
    attribution: basemap.attribution,
    subdomains:  basemap.subdomains,
    maxZoom:     basemap.maxZoom,
  }).addTo(map);
}

// ═══════════════════════════════════════════════════════════════════════
// Marker tooltips
// ═══════════════════════════════════════════════════════════════════════

/**
 * Build HTML for a marker tooltip.
 * @param {'src'|'dst'} role
 * @param {object} geo
 */
function buildTooltipHtml(role, geo) {
  const lines = [`${role === 'src' ? 'SRC' : 'DST'} ${escapeHtml(geo.ip)}`];
  if (geo.hostname && geo.hostname !== geo.ip) {
    lines.push(`<span class="host">${escapeHtml(geo.hostname)}</span>`);
  }
  const place = [geo.city, geo.country].filter(Boolean).join(', ');
  if (place) lines.push(escapeHtml(place));
  if (geo.external_ip && geo.is_local) lines.push(`via ${escapeHtml(geo.external_ip)}`);
  if (geo.is_local) lines.push('(local)');
  return lines.join('<br>');
}

/** Create (or return the existing) marker for an IP. */
function ensureMarker(ip, geo, role) {
  const mapKey   = `${role}:${ip}`;
  const existing = ipMarkers.get(mapKey);
  if (existing) return existing.marker;

  const isLocal = !!geo.is_local;
  const [lat, lon] = coordsFor(geo);

  const style = role === 'src'
    ? { radius: 6, color: '#22d3ee', weight: 2, fillColor: '#22d3ee', fillOpacity: 0.9 }
    : { radius: 5, color: '#f1f5f9', weight: 1.5, fillColor: '#0b1120', fillOpacity: 0.7 };

  const marker = L.circleMarker([lat, lon], style)
    .bindTooltip(buildTooltipHtml(role, geo), {
      direction: 'top', className: 'netviz-tip',
    })
    .addTo(map);

  if (isLocal) {
    L.circleMarker([lat, lon], {
      radius: 14, color: '#22d3ee', weight: 1,
      fill: false, opacity: 0.4, className: 'pulse',
    }).addTo(map);
  }

  ipMarkers.set(mapKey, {
    marker,
    lastHostname: geo.hostname || null,
    lastExternal: geo.external_ip || null,
  });
  return marker;
}

/** Refresh a marker tooltip only if its data actually changed. */
function updateMarkerTooltip(role, geo) {
  const mapKey = `${role}:${geo.ip}`;
  const state  = ipMarkers.get(mapKey);
  if (!state) return;

  const hn  = geo.hostname || null;
  const ext = geo.external_ip || null;
  if (state.lastHostname === hn && state.lastExternal === ext) return;

  state.lastHostname = hn;
  state.lastExternal = ext;
  const tt = state.marker.getTooltip();
  if (tt) tt.setContent(buildTooltipHtml(role, geo));
}

// ═══════════════════════════════════════════════════════════════════════
// Reference counting for markers
// ═══════════════════════════════════════════════════════════════════════

/** Add a flow reference for both endpoint IPs. */
function addIpRefs(srcIp, dstIp, flowKey) {
  for (const [ip, role] of [[srcIp, 'src'], [dstIp, 'dst']]) {
    const k = `${role}:${ip}`;
    if (!ipRefs.has(k)) ipRefs.set(k, new Set());
    ipRefs.get(k).add(flowKey);
  }
}

/** Drop a flow reference; remove the marker when the last ref goes away. */
function removeIpRefs(srcIp, dstIp, flowKey) {
  for (const [ip, role] of [[srcIp, 'src'], [dstIp, 'dst']]) {
    const k   = `${role}:${ip}`;
    const set = ipRefs.get(k);
    if (!set) continue;
    set.delete(flowKey);
    if (set.size === 0) {
      ipRefs.delete(k);
      const state = ipMarkers.get(k);
      if (state) { map.removeLayer(state.marker); ipMarkers.delete(k); }
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Direction arrow
// ═══════════════════════════════════════════════════════════════════════

/** Draw a triangular arrowhead near the destination of a src→dst line. */
function drawArrow(srcGeo, dstGeo, color, opts = {}) {
  const [sLat, sLon] = coordsFor(srcGeo);
  const [dLat, dLon] = coordsFor(dstGeo);

  const p1 = map.latLngToLayerPoint([sLat, sLon]);
  const p2 = map.latLngToLayerPoint([dLat, dLon]);

  const ang       = Math.atan2(p2.y - p1.y, p2.x - p1.x);
  const len       = 12;
  const tipOffset = 8;

  const tip   = { x: p2.x - Math.cos(ang) * tipOffset,
                  y: p2.y - Math.sin(ang) * tipOffset };
  const left  = { x: tip.x - Math.cos(ang - 0.5) * len,
                  y: tip.y - Math.sin(ang - 0.5) * len };
  const right = { x: tip.x - Math.cos(ang + 0.5) * len,
                  y: tip.y - Math.sin(ang + 0.5) * len };

  const toLL = p => map.layerPointToLatLng(L.point(p.x, p.y));
  return L.polyline([toLL(left), toLL(tip), toLL(right)], {
    color, weight: opts.weight || 2, opacity: opts.opacity ?? 0.9,
    interactive: false,
  }).addTo(map);
}

// ═══════════════════════════════════════════════════════════════════════
// Highlight logic (active flows + ghost for expired ones)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Highlight (or un-highlight) all active flows matching a connection key.
 * Returns the number of matched flows.
 */
function applyHighlight(connKey, on) {
  let matched = 0;
  for (const [, item] of flows.entries()) {
    const f = item.flow;
    if (!f || !f.src || !f.dst) continue;
    if (connKeyStr(f.src.ip, f.dst.ip) !== connKey) continue;

    matched++;
    item.highlighted = on;

    if (on) {
      item.layer.setStyle({ color: HIGHLIGHT_COLOR, weight: 5, opacity: 1 });
      if (item.arrow) item.arrow.setStyle({ color: HIGHLIGHT_COLOR, opacity: 1 });
      item.layer.bringToFront();
      if (item.arrow) item.arrow.bringToFront();
    } else {
      const color = protoColor(f.proto);
      item.layer.setStyle({ color, weight: 2, opacity: 0.9 });
      if (item.arrow) item.arrow.setStyle({ color, opacity: 0.9 });
    }
  }
  return matched;
}

/** Draw a temporary red line for a connection with no active flow. */
function createGhost(connKey) {
  const conn = connections.get(connKey);
  if (!conn) return;

  const { srcGeo, dstGeo } = conn;
  if (!hasValidGeo(srcGeo) || !hasValidGeo(dstGeo)) return;

  const [sLat, sLon] = coordsFor(srcGeo);
  const [dLat, dLon] = coordsFor(dstGeo);
  const color        = HIGHLIGHT_COLOR;

  const layer = L.polyline([[sLat, sLon], [dLat, dLon]], {
    color, weight: 5, opacity: 1, dashArray: '6 6',
  }).addTo(map);

  const arrow = drawArrow(srcGeo, dstGeo, color, { weight: 3, opacity: 1 });

  const sm = L.circleMarker([sLat, sLon], {
    radius: 6, color, weight: 2, fillColor: color, fillOpacity: 0.9,
  }).addTo(map);
  const dm = L.circleMarker([dLat, dLon], {
    radius: 5, color, weight: 2, fillColor: '#0b1120', fillOpacity: 0.7,
  }).addTo(map);

  highlightGhost = { layer, arrow, sm, dm };
}

/** Remove all temporary ghost layers. */
function removeGhost() {
  if (!highlightGhost) return;
  for (const k of ['layer', 'arrow', 'sm', 'dm']) {
    const l = highlightGhost[k];
    if (l) map.removeLayer(l);
  }
  highlightGhost = null;
}

/** Remove highlight from active flows and any ghost layers. */
function clearHighlight() {
  if (highlightedConn) applyHighlight(highlightedConn, false);
  removeGhost();
}

function onRowEnter(connKey) {
  if (highlightedConn === connKey) return;
  clearHighlight();
  highlightedConn = connKey;
  const matched = applyHighlight(connKey, true);
  if (matched === 0) createGhost(connKey);
}

function onRowLeave(connKey) {
  if (highlightedConn !== connKey) return;
  clearHighlight();
  highlightedConn = null;
}

/** Attach hover handlers to a connection row. */
function attachRowHover(row, connKey) {
  row.addEventListener('mouseenter', () => onRowEnter(connKey));
  row.addEventListener('mouseleave', () => onRowLeave(connKey));
}

// ═══════════════════════════════════════════════════════════════════════
// Filter / search
// ═══════════════════════════════════════════════════════════════════════

/**
 * Decide whether a single connection matches the active filter.
 *
 * The comparison is case-insensitive and checks:
 *   * source IP
 *   * destination IP
 *   * source hostname
 *   * destination hostname
 *   * protocol name (TCP / UDP / ICMP)
 */
function connectionMatchesFilter(conn) {
  if (!filterQuery) return true;

  const haystack = [
    conn.srcIp,
    conn.dstIp,
    conn.srcGeo && conn.srcGeo.hostname,
    conn.dstGeo && conn.dstGeo.hostname,
    PROTO_NAME[conn.proto],
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  return haystack.includes(filterQuery);
}

/**
 * Apply the current filter to every connection row.
 *
 * Rows that do not match get the `.filtered-out` class, which hides them
 * via CSS. The "no matching connections" hint is shown when there are
 * rows but none are visible.
 */
function applyFilter() {
  let visible = 0;
  let total   = 0;

  for (const conn of connections.values()) {
    total++;
    const match = connectionMatchesFilter(conn);
    conn.el.classList.toggle('filtered-out', !match);
    if (match) visible++;
  }

  if (elConnEmpty) {
    elConnEmpty.hidden = !(filterQuery && total > 0 && visible === 0);
  }
}

/** Called whenever the user types in the search box. */
function onSearchInput() {
  filterQuery = elSearch.value.trim().toLowerCase();
  applyFilter();
}

/** Clear the filter and reset the input. */
function clearSearch() {
  elSearch.value = '';
  filterQuery    = '';
  applyFilter();
}

// Wire up the filter bar.
elSearch.addEventListener('input', onSearchInput);
elSearchClear.addEventListener('click', () => {
  clearSearch();
  elSearch.focus();
});
// "Escape" clears the filter, matching the usual search-field behaviour.
elSearch.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    e.stopPropagation();
    clearSearch();
  }
});

// ═══════════════════════════════════════════════════════════════════════
// Connection list UI
// ═══════════════════════════════════════════════════════════════════════

/** Create or update the connection row for (srcGeo → dstGeo). */
function upsertConnection(srcGeo, dstGeo, proto) {
  const key = connKeyStr(srcGeo.ip, dstGeo.ip);
  let conn  = connections.get(key);

  if (!conn) {
    const row = document.createElement('label');
    row.className = 'conn-row';

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = true;
    cb.dataset.key = key;
    cb.addEventListener('change', onCheckboxChange);

    const text = document.createElement('span');
    text.className = 'conn-text';

    row.appendChild(cb);
    row.appendChild(text);
    elConnList.appendChild(row);
    attachRowHover(row, key);

    conn = {
      srcIp: srcGeo.ip, dstIp: dstGeo.ip,
      srcGeo, dstGeo, proto, ignored: false,
      el: row, cb, text,
    };
    connections.set(key, conn);
  } else {
    conn.srcGeo = srcGeo;
    conn.dstGeo = dstGeo;
  }

  renderConnectionText(conn);
  refreshConnCount();
  return conn;
}

/** Re-render the text (and title) of a single connection row. */
function renderConnectionText(conn) {
  const srcLabel = conn.srcGeo.hostname || conn.srcIp;
  const dstLabel = conn.dstGeo.hostname || conn.dstIp;
  const proto    = PROTO_NAME[conn.proto] || conn.proto || '';

  conn.text.innerHTML =
    `<span class="ip">${escapeHtml(srcLabel)}</span>` +
    `<span class="arrow">→</span>` +
    `<span class="ip">${escapeHtml(dstLabel)}</span>` +
    (proto ? `<span class="proto">${escapeHtml(proto)}</span>` : '');

  conn.el.title =
    `${conn.srcIp}${conn.srcGeo.hostname ? ' (' + conn.srcGeo.hostname + ')' : ''}\n` +
    `→ ${conn.dstIp}${conn.dstGeo.hostname ? ' (' + conn.dstGeo.hostname + ')' : ''}\n` +
    `proto: ${proto || '?'}`;

  conn.el.classList.toggle('ignored', conn.ignored);

  // The visible text (which may include a fresh hostname) might now match
  // or no longer match the current filter — reapply it for this row.
  conn.el.classList.toggle('filtered-out', !connectionMatchesFilter(conn));
}

/** Update the header counter and the select-all tri-state. */
function refreshConnCount() {
  elConnCount.textContent = connections.size;
  updateSelectAllState();
  applyFilter();
}

/**
 * Synchronise the header "All" checkbox with the current per-row states.
 *
 * - every row checked  → checked
 * - every row unchecked → unchecked
 * - mixed               → indeterminate
 * - no rows             → unchecked
 */
function updateSelectAllState() {
  if (!elSelectAll) return;

  const total = connections.size;
  if (total === 0) {
    elSelectAll.checked       = false;
    elSelectAll.indeterminate = false;
    return;
  }

  let checkedCount = 0;
  for (const conn of connections.values()) {
    if (conn.cb.checked) checkedCount++;
  }

  if (checkedCount === total) {
    elSelectAll.checked       = true;
    elSelectAll.indeterminate = false;
  } else if (checkedCount === 0) {
    elSelectAll.checked       = false;
    elSelectAll.indeterminate = false;
  } else {
    elSelectAll.checked       = false;
    elSelectAll.indeterminate = true;
  }
}

/**
 * Handle a single row's checkbox change.
 *
 * Also invoked programmatically by the "All" toggle, so it must not rely
 * on the event object beyond `ev.target`.
 */
function onCheckboxChange(ev) {
  const cb   = ev.target;
  const key  = cb.dataset.key;
  const conn = connections.get(key);
  if (!conn) return;

  const wantIgnore = !cb.checked;
  conn.ignored = wantIgnore;
  conn.el.classList.toggle('ignored', wantIgnore);

  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({
      type:     'set_ignore',
      conn_key: [conn.srcIp, conn.dstIp],
      ignored:  wantIgnore,
    }));
  }

  updateSelectAllState();
}

/** Remove all flows matching a given (srcIp, dstIp) pair. */
function removeFlowsByConnection(srcIp, dstIp) {
  const connKey = connKeyStr(srcIp, dstIp);
  for (const [fkey, item] of [...flows.entries()]) {
    const f = item.flow;
    if (!f || !f.src || !f.dst) continue;
    if (f.src.ip !== srcIp || f.dst.ip !== dstIp) continue;

    [item.layer, item.arrow].filter(Boolean).forEach(l => map.removeLayer(l));
    removeIpRefs(f.src.ip, f.dst.ip, fkey);
    flows.delete(fkey);
  }
  if (highlightedConn === connKey) {
    removeGhost();
    highlightedConn = null;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Select-All behaviour
// ═══════════════════════════════════════════════════════════════════════

/**
 * Apply a target checked-state to every connection row.
 *
 * Uses `onCheckboxChange` so the UI update path stays identical to a
 * manual click (including sending the WS `set_ignore` message).
 */
function applySelectAll(targetChecked) {
  for (const conn of connections.values()) {
    if (conn.cb.checked === targetChecked) continue;
    conn.cb.checked = targetChecked;
    onCheckboxChange({ target: conn.cb });
  }
  updateSelectAllState();
}

// User clicked the "All" checkbox itself
elSelectAll.addEventListener('change', () => {
  applySelectAll(elSelectAll.checked);
});

// ═══════════════════════════════════════════════════════════════════════
// Flow lifecycle handlers
// ═══════════════════════════════════════════════════════════════════════

/** Handle a `flow_up` message: create/refresh the line + arrow. */
function onFlowUp(msg) {
  const f     = msg.flow;
  const key   = keyStr(f.key);
  const color = protoColor(f.proto);

  const conn = upsertConnection(f.src, f.dst, f.proto);
  if (conn.ignored) return;

  if (flows.has(key)) {
    const item = flows.get(key);
    if (!item.highlighted) {
      item.layer.setStyle({ color, opacity: 0.9, weight: 2 });
      if (item.arrow) item.arrow.setStyle({ color, opacity: 0.9 });
    }
    item.flow = f;
    return;
  }

  ensureMarker(f.src.ip, f.src, 'src');
  ensureMarker(f.dst.ip, f.dst, 'dst');
  addIpRefs(f.src.ip, f.dst.ip, key);

  const [sLat, sLon] = coordsFor(f.src);
  const [dLat, dLon] = coordsFor(f.dst);

  const line = L.polyline([[sLat, sLon], [dLat, dLon]],
    { color, weight: 2, opacity: 0.9 })
    .bindTooltip(
      `SRC ${escapeHtml(f.src.ip)} → DST ${escapeHtml(f.dst.ip)}<br>proto ${f.proto}`,
      { sticky: true },
    )
    .addTo(map);

  const arrow = drawArrow(f.src, f.dst, color);
  const isHighlighted = highlightedConn === connKeyStr(f.src.ip, f.dst.ip);

  const item = { layer: line, arrow, flow: f, highlighted: isHighlighted };
  flows.set(key, item);

  if (isHighlighted) {
    line.setStyle({ color: HIGHLIGHT_COLOR, weight: 5, opacity: 1 });
    arrow.setStyle({ color: HIGHLIGHT_COLOR, opacity: 1 });
    line.bringToFront();
    arrow.bringToFront();
    removeGhost();
  }
}

/** Handle a `flow_down` message: fade out and remove the layers. */
function onFlowDown(msg) {
  const key  = keyStr(msg.key);
  const item = flows.get(key);
  if (!item) return;

  const layers = [item.layer, item.arrow].filter(Boolean);
  let opacity  = item.layer.options.opacity ?? 0.9;

  const step = () => {
    opacity -= 0.08;
    if (opacity <= 0) { layers.forEach(l => map.removeLayer(l)); return; }
    layers.forEach(l => l.setStyle({ opacity }));
    requestAnimationFrame(step);
  };
  requestAnimationFrame(step);

  flows.delete(key);
  removeIpRefs(item.flow.src.ip, item.flow.dst.ip, key);
}

/** Handle a periodic `tick` snapshot: update opacity / weight / tooltips. */
function onTick(msg) {
  const now = Date.now() / 1000;
  for (const snap of msg.flows) {
    const key  = keyStr(snap.key);
    const item = flows.get(key);
    if (!item) continue;

    item.flow = snap;

    if (!item.highlighted) {
      const idle    = now - snap.last_seen;
      const opacity = Math.max(0.15, Math.min(0.95, 1 - idle / 2.5));
      const weight  = Math.min(6, 1.5 + Math.log10(1 + (snap.bps || 0) / 2000));
      item.layer.setStyle({ opacity, weight });
      if (item.arrow) item.arrow.setStyle({ opacity });
    }

    if (snap.src) updateMarkerTooltip('src', snap.src);
    if (snap.dst) updateMarkerTooltip('dst', snap.dst);

    const conn = connections.get(connKeyStr(snap.src.ip, snap.dst.ip));
    if (conn) {
      conn.srcGeo = snap.src;
      conn.dstGeo = snap.dst;
      renderConnectionText(conn);   // also re-applies the filter to this row
    }
  }
}

/** Handle an `ignore_changed` acknowledgement from the backend. */
function onIgnoreChanged(msg) {
  const [srcIp, dstIp] = msg.conn_key;
  const key  = connKeyStr(srcIp, dstIp);
  const conn = connections.get(key);
  if (!conn) return;

  conn.ignored = !!msg.ignored;
  conn.cb.checked = !conn.ignored;
  conn.el.classList.toggle('ignored', conn.ignored);

  if (conn.ignored) removeFlowsByConnection(srcIp, dstIp);

  updateSelectAllState();
}

/** Handle the `local_ip_changed` event. */
function onLocalIpChanged(msg) {
  if (elExtIp) elExtIp.textContent = msg.external.ip;
  console.log('[netviz] external IP changed →', msg.external.ip);
}

// ═══════════════════════════════════════════════════════════════════════
// Stats & UI chrome
// ═══════════════════════════════════════════════════════════════════════

function refreshStats() {
  elFlows.textContent = flows.size;
  elIPs.textContent   = ipMarkers.size;
}
setInterval(refreshStats, 500);

// Header click → collapse / expand. Clicks inside the select-all label
// are ignored so that toggling "All" does not collapse the panel.
elConnHeader.addEventListener('click', (ev) => {
  if (ev.target.closest('.select-all-wrap')) return;
  elConnBox.classList.toggle('collapsed');
  const btn = document.getElementById('conn-toggle');
  btn.textContent = elConnBox.classList.contains('collapsed') ? '▸' : '▾';
});

// ═══════════════════════════════════════════════════════════════════════
// WebSocket
// ═══════════════════════════════════════════════════════════════════════

/** Replay the ignore list received in the `init` message. */
function renderInitIgnores(list) {
  (list || []).forEach(([s, d]) => {
    const key = connKeyStr(s, d);
    if (connections.has(key)) return;

    const row = document.createElement('label');
    row.className = 'conn-row ignored';

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = false;
    cb.dataset.key = key;
    cb.addEventListener('change', onCheckboxChange);

    const text = document.createElement('span');
    text.className = 'conn-text';
    text.textContent = `${s} → ${d}`;

    row.appendChild(cb);
    row.appendChild(text);
    elConnList.appendChild(row);
    attachRowHover(row, key);

    connections.set(key, {
      srcIp: s, dstIp: d,
      srcGeo: { ip: s, hostname: null },
      dstGeo: { ip: d, hostname: null },
      proto: null, ignored: true,
      el: row, cb, text,
    });
  });
  refreshConnCount();
}

/** Route an incoming WebSocket message to the correct handler. */
function dispatchMessage(msg) {
  switch (msg.type) {
    case 'init':
      renderInitIgnores(msg.ignored);
      msg.flows.forEach(f => onFlowUp({ flow: f }));
      if (msg.external && elExtIp) elExtIp.textContent = msg.external.ip;
      break;
    case 'flow_up':          onFlowUp(msg); break;
    case 'flow_down':        onFlowDown(msg); break;
    case 'tick':             onTick(msg); break;
    case 'ignore_changed':   onIgnoreChanged(msg); break;
    case 'local_ip_changed': onLocalIpChanged(msg); break;
    default: console.warn('[netviz] unknown message', msg);
  }
}

/** Open the WebSocket connection and wire up handlers. */
function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => {
    elStatus.textContent = 'connected';
    elStatus.style.color = '#22c55e';
  };
  ws.onclose = () => {
    elStatus.textContent = 'reconnecting…';
    elStatus.style.color = '#f59e0b';
    setTimeout(connect, 2000);
  };
  ws.onerror = () => ws.close();

  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    dispatchMessage(msg);
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Bootstrap
// ═══════════════════════════════════════════════════════════════════════

(async function bootstrap() {
  try {
    await loadConfig();
  } catch (e) {
    console.error('[netviz] failed to load config:', e);
    elStatus.textContent = 'config error';
    elStatus.style.color = '#ef4444';
    return;
  }
  initMap();
  connect();
})();
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = (value) => String(value ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function api(path, body) {
  const res = await fetch(path, body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(text || `${res.status}`);
  return text ? JSON.parse(text) : {};
}

let toastTimer;
function toast(message, bad = false) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.toggle("bad", bad);
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 4500);
}

// ── tabs ────────────────────────────────────────────────────────────────
$$(".tab").forEach((tab) => tab.onclick = () => {
  $$(".tab").forEach((t) => t.classList.remove("active"));
  $$(".panel").forEach((p) => p.classList.remove("active"));
  tab.classList.add("active");
  $(`#tab-${tab.dataset.tab}`).classList.add("active");
});

// ── settings / setup drawer ─────────────────────────────────────────────
let SETTINGS = {};

async function loadSettings() {
  SETTINGS = await api("/api/settings");
  $("#set-base-url").value = SETTINGS.base_url || "";
  $("#set-model").value = SETTINGS.model || "";
  $("#set-no-thinking").checked = !!SETTINGS.no_thinking;
  $("#set-cache").checked = !!SETTINGS.cache;
  $$("#backend-seg button").forEach((b) => b.classList.toggle("active", b.dataset.backend === SETTINGS.backend));
  $("#status-pills").innerHTML = [
    pill("backend", SETTINGS.backend, SETTINGS.backend === "scripted" ? "" : "ok"),
    SETTINGS.backend === "scripted" ? pill("model", "offline") : pill("model", SETTINGS.model || "—", SETTINGS.model ? "ok" : "warn"),
    SETTINGS.backend === "cloud" ? pill("api key", SETTINGS.api_key_set ? "set" : "missing", SETTINGS.api_key_set ? "ok" : "bad") : "",
    pill("analyzer", SETTINGS.openai_ready ? "ready" : "missing", SETTINGS.openai_ready ? "ok" : "bad"),
    pill("cache", SETTINGS.cache ? "on" : "off"),
  ].join("");
}
const pill = (label, value, cls = "") => `<span class="pill ${cls}">${esc(label)} <b>${esc(value)}</b></span>`;

function openSetup(open) {
  $("#setup-drawer").classList.toggle("open", open);
  $("#setup-drawer").setAttribute("aria-hidden", String(!open));
}
const currentBackend = () => $("#backend-seg button.active")?.dataset.backend || "scripted";

$("#open-setup").onclick = () => {
  openSetup(true);
  if (currentBackend() === "local") detectLocal();
};
$("#close-setup").onclick = () => openSetup(false);
$$("#backend-seg button").forEach((b) => b.onclick = () => {
  $$("#backend-seg button").forEach((x) => x.classList.remove("active"));
  b.classList.add("active");
  if (b.dataset.backend === "local") detectLocal();
});
$("#set-save").onclick = async () => {
  const payload = {
    backend: $("#backend-seg button.active")?.dataset.backend || "scripted",
    base_url: $("#set-base-url").value.trim(),
    model: $("#set-model").value.trim(),
    no_thinking: $("#set-no-thinking").checked,
    cache: $("#set-cache").checked,
  };
  const key = $("#set-api-key").value.trim();
  if (key) payload.api_key = key;
  try {
    await api("/api/settings", payload);
    $("#set-api-key").value = "";
    await loadSettings();
    toast("Settings saved");
  } catch (e) { toast(`Could not save: ${e.message}`, true); }
};
$("#set-test").onclick = async () => {
  $("#set-status").textContent = "Testing…";
  try {
    const r = await api("/api/test", {});
    $("#set-status").textContent = r.ok ? `OK — ${r.backend} ${r.model}` : `Failed — ${r.error}`;
    toast(r.ok ? "Connection OK" : "Connection failed", !r.ok);
  } catch (e) { $("#set-status").textContent = e.message; }
};

// Auto-recognize the models a local endpoint serves, so the user need not type one.
async function detectLocal() {
  const status = $("#set-status");
  status.textContent = "Auto-recognizing local models…";
  try {
    const r = await api("/api/local/models");
    if (!r.ok) { status.textContent = `Local detect failed — ${r.error}`; return; }
    $("#local-models").innerHTML = (r.models || []).map((m) => `<option value="${esc(m)}"></option>`).join("");
    const field = $("#set-model");
    if (!field.value.trim() || field.value.trim().toLowerCase() === "auto") field.value = "auto";
    const n = (r.models || []).length;
    status.textContent = `Local endpoint ${r.base_url} — recognized: ${r.model || "none"}` +
      (n ? ` (${n} model${n === 1 ? "" : "s"} available)` : "");
    toast(`Local model recognized: ${r.model || "none"}`);
  } catch (e) { status.textContent = `Local detect failed — ${e.message}`; }
}
$("#set-detect").onclick = detectLocal;

// ── folder browser ──────────────────────────────────────────────────────
let browse = { path: null, parent: null, selected: null };
$("#browse-btn").onclick = async () => {
  $("#browser-modal").classList.add("open");
  await loadBrowse(null);
};
$("#close-browser").onclick = () => $("#browser-modal").classList.remove("open");
$("#browser-up").onclick = () => browse.parent && loadBrowse(browse.parent);
$("#browser-home").onclick = () => loadBrowse(browse.home || null);
$("#browser-choose").onclick = () => {
  const chosen = browse.selected || browse.path;
  if (!chosen) return;
  $("#browser-modal").classList.remove("open");
  chooseFolder(chosen);
};

async function loadBrowse(path) {
  const data = await api(`/api/browse${path ? `?path=${encodeURIComponent(path)}` : ""}`);
  browse = { path: data.path, parent: data.parent, home: data.home, selected: null };
  $("#browser-path").textContent = data.path || "";
  const list = $("#browser-list");
  list.innerHTML = (data.entries || []).map((e) => `<li data-path="${esc(e.path)}">📁 ${esc(e.name)}</li>`).join("")
    || `<li class="muted">(no sub-folders)</li>`;
  $$("#browser-list li[data-path]").forEach((li) => {
    li.onclick = () => {
      $$("#browser-list li").forEach((x) => x.classList.remove("sel"));
      li.classList.add("sel");
      browse.selected = li.dataset.path;
    };
    li.ondblclick = () => loadBrowse(li.dataset.path);
  });
}

async function chooseFolder(path) {
  $("#review-path").value = path;
  $("#run-hint").textContent = "";
  await inspect(path);
}

// Allow typing a path directly (fallback when browsing is inconvenient).
for (const evt of ["change", "keydown"]) {
  $("#review-path").addEventListener(evt, (e) => {
    if (evt === "keydown" && e.key !== "Enter") return;
    const p = $("#review-path").value.trim();
    if (p) inspect(p);
  });
}

async function inspect(path) {
  const box = $("#inspect");
  box.textContent = "Inspecting…";
  try {
    const report = await api(`/api/inspect?path=${encodeURIComponent(path)}`);
    if (report.error) { box.textContent = report.error; return; }
    const langs = (report.by_language || []).map((l) => {
      const cls = l.status === "covered" ? "tag-ok" : l.status === "unsupported" ? "tag-bad" : "tag-warn";
      return `<span class="lang"><b>${esc(l.language)}</b> · ${l.files} files · <span class="${cls}">${esc(l.status)}</span></span>`;
    }).join("") || "<span class='muted'>no supported files found</span>";
    const unchecked = (report.unchecked_languages || []).length
      ? `<div class="muted">Unchecked languages: ${report.unchecked_languages.map(esc).join(", ")}</div>` : "";
    box.innerHTML = `<div>${report.files_total} files · checked ${Math.round((report.checked_fraction || 0) * 100)}%</div>${langs}${unchecked}`;
    $("#review-run").disabled = false;
    $("#audit-run").disabled = false;
    $("#fn-list").disabled = false;
    $("#fn-box").innerHTML = "";
    $("#fn-status").textContent = "";
    FUNCS = [];
  } catch (e) { box.textContent = `Could not inspect: ${e.message}`; }
}

// ── review run ──────────────────────────────────────────────────────────
let RESULTS = { rows: [], summary: {} };

$("#review-run").onclick = async () => {
  const path = $("#review-path").value.trim();
  if (!path) return;
  const button = $("#review-run");
  button.disabled = true;
  $("#review-error").classList.add("hidden");
  $("#review-results").classList.add("hidden");
  $("#review-summary").innerHTML = "";
  try {
    const { id } = await api("/api/jobs", {
      kind: "review",
      params: { path, verifier: $("#review-verifier").value, limit: Number($("#review-limit").value || 0) },
    });
    const result = await poll(id, "#review-progress");
    RESULTS = { rows: result.rows || [], summary: result.summary || {} };
    renderSummary();
    renderTable();
    $("#review-results").classList.remove("hidden");
    toast(`Done — ${RESULTS.rows.length} candidates`);
  } catch (e) {
    $("#review-error").textContent = e.message;
    $("#review-error").classList.remove("hidden");
  } finally { button.disabled = false; }
};

$("#audit-run").onclick = async () => {
  const path = $("#review-path").value.trim();
  if (!path) return;
  const button = $("#audit-run");
  button.disabled = true;
  $("#review-error").classList.add("hidden");
  $("#audit-results").classList.add("hidden");
  $("#audit-summary").innerHTML = "";
  try {
    const max_functions = Number($("#review-limit").value || 0);
    const { id } = await api("/api/jobs", { kind: "audit", params: { path, max_functions } });
    const result = await poll(id, "#review-progress");
    renderAudit(result);
    $("#audit-results").classList.remove("hidden");
    toast(`Audit done — ${(result.summary || {}).findings || 0} findings`);
  } catch (e) {
    $("#review-error").textContent = e.message;
    $("#review-error").classList.remove("hidden");
  } finally { button.disabled = false; }
};

function renderAudit(result) {
  const s = result.summary || {};
  $("#audit-summary").innerHTML = [
    stat("functions", s.functions_audited),
    stat("findings", s.findings, s.findings ? "warn" : ""),
    stat("verified refs", s.verified),
    stat("files", s.files_audited),
    stat("unchecked", (s.unchecked_languages || []).join(", ") || "0",
         (s.unchecked_languages || []).length ? "warn" : ""),
  ].join("");
  const rows = [];
  (result.results || []).forEach((r) => (r.findings || []).forEach((f) => rows.push({ f, r })));
  const tbody = $("#audit-table tbody");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="muted">No mistakes reported.</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(({ f }, i) => `
    <tr class="clickable" data-i="${i}" title="click to view the code">
      <td><code>${esc(f.path)}:${esc(f.line)}</code>${f.verified ? "" : " <span class='muted'>(unverified)</span>"}</td>
      <td>${esc(f.severity)}</td>
      <td>${esc(f.kind)}${f.cwe ? `<div class="muted">${esc(f.cwe)}</div>` : ""}</td>
      <td>${esc(f.confidence)}</td>
      <td>${esc(f.rationale)}</td>
    </tr>`).join("");
  $$("#audit-table tbody tr.clickable").forEach((tr) => tr.onclick = () => {
    const next = tr.nextElementSibling;
    if (next && next.classList.contains("detailrow")) { next.remove(); return; }
    const { f, r } = rows[Number(tr.dataset.i)];
    const detail = document.createElement("tr");
    detail.className = "detailrow";
    detail.innerHTML = `<td class="detail" colspan="5">
      <div><b>${esc(r.path)}::${esc(r.name)}</b> <span class="muted">(lines ${esc(r.start_line)}–${esc(r.end_line)})</span></div>
      ${r.snippet ? `<pre class="snippet" style="max-height:280px;overflow:auto;margin:6px 0;padding:8px;background:rgba(128,128,128,.12);border-radius:6px">${esc(r.snippet)}</pre>` : ""}
      <div class="muted">why: ${esc(f.rationale || "—")}</div>
    </td>`;
    tr.after(detail);
  });
}

// ── selective function audit ────────────────────────────────────────────
let FUNCS = [];
const SEL = new Set();

function updateFnStatus(extra = "") {
  $("#fn-audit").disabled = SEL.size === 0;
  $("#fn-status").textContent = extra || (SEL.size ? `${SEL.size} selected` : "");
}

function renderFunctions(extra = "") {
  const filter = $("#fn-filter").value.trim().toLowerCase();
  const shown = FUNCS.map((f, i) => ({ f, i }))
    .filter(({ f }) => !filter || `${f.path} ${f.name}`.toLowerCase().includes(filter));
  $("#fn-box").innerHTML = shown.map(({ f, i }) =>
    `<label style="display:block;padding:2px 0"><input type="checkbox" data-i="${i}" ${SEL.has(i) ? "checked" : ""}/> ` +
    `<code>${esc(f.path)}:${f.start_line}</code> <b>${esc(f.name)}</b> ` +
    `<span class="muted">(${f.lines} lines)</span></label>`).join("")
    || `<span class="muted">No functions. Pick a folder and click List functions.</span>`;
  $$("#fn-box input[type=checkbox]").forEach((cb) => cb.onchange = () => {
    const i = Number(cb.dataset.i);
    if (cb.checked) SEL.add(i); else SEL.delete(i);
    updateFnStatus();
  });
  updateFnStatus(extra);
}

$("#fn-list").onclick = async () => {
  const path = $("#review-path").value.trim();
  if (!path) return;
  $("#fn-status").textContent = "Listing functions…";
  try {
    const r = await api(`/api/functions?path=${encodeURIComponent(path)}`);
    if (r.error) { $("#fn-status").textContent = r.error; return; }
    FUNCS = r.functions || [];
    SEL.clear();
    renderFunctions(`${FUNCS.length} functions in ${r.root}`);
  } catch (e) { $("#fn-status").textContent = `Could not list: ${e.message}`; }
};
$("#fn-filter").oninput = () => renderFunctions($("#fn-status").textContent);
$("#fn-all").onchange = () => {
  const on = $("#fn-all").checked;
  const filter = $("#fn-filter").value.trim().toLowerCase();
  FUNCS.forEach((f, i) => {
    if (!filter || `${f.path} ${f.name}`.toLowerCase().includes(filter)) {
      if (on) SEL.add(i); else SEL.delete(i);
    }
  });
  renderFunctions();
};
$("#fn-audit").onclick = async () => {
  const path = $("#review-path").value.trim();
  const chosen = [...SEL].map((i) => FUNCS[i]).filter(Boolean);
  if (!path || !chosen.length) { toast("Select at least one function", true); return; }
  const button = $("#fn-audit");
  button.disabled = true;
  $("#audit-results").classList.add("hidden");
  $("#audit-summary").innerHTML = "";
  $("#fn-status").textContent = `Auditing ${chosen.length} function(s) via cloud…`;
  try {
    const { id } = await api("/api/jobs", {
      kind: "audit",
      params: { path, backend: "cloud",
                functions: chosen.map((f) => ({ path: f.path, start_line: f.start_line })) },
    });
    const result = await poll(id, "#review-progress");
    renderAudit(result);
    $("#audit-results").classList.remove("hidden");
    $("#fn-status").textContent = `Done — ${(result.summary || {}).findings || 0} findings`;
    toast("Selective audit done");
  } catch (e) { $("#fn-status").textContent = e.message; toast(e.message, true); }
  finally { button.disabled = false; }
};

function renderSummary() {
  const s = RESULTS.summary, cov = s.coverage || {};
  $("#review-summary").innerHTML = [
    stat("candidates", s.candidates),
    stat("true positive", s.true_positive, "ok"),
    stat("false positive", s.false_positive, "bad"),
    stat("abstained", s.unknown_risk, "warn"),
    stat("reachable paths", s.reachable),
    stat("skipped (non-code)", s.skipped_noncode || 0, (s.skipped_noncode || 0) ? "warn" : ""),
    stat("checked", `${Math.round((cov.checked_fraction || 0) * 100)}%`),
    stat("unchecked langs", (cov.unchecked_languages || []).length || "0", (cov.unchecked_languages || []).length ? "warn" : ""),
    stat("tokens", `${s.tokens_in || 0} / ${s.tokens_out || 0}`),
  ].join("");
}
const stat = (k, v, cls = "") => `<div class="stat ${cls}"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`;

function filteredRows() {
  const verdict = $("#filter-verdict").value;
  const needle = $("#filter-search").value.trim().toLowerCase();
  return RESULTS.rows.filter((r) => {
    if (verdict && r.disposition !== verdict) return false;
    if (needle && !`${r.path} ${r.rule} ${r.rationale} ${(r.hops || []).join(" ")}`.toLowerCase().includes(needle)) return false;
    return true;
  });
}

const verdictClass = (d) => d === "true_positive" ? "tp" : d === "false_positive" ? "fp" : "ur";

function renderTable() {
  const rows = filteredRows();
  const tbody = $("#review-table tbody");
  $("#review-empty").classList.toggle("hidden", rows.length > 0);
  tbody.innerHTML = rows.map((r, i) => {
    const path = r.entry ? `<span class="path">${esc(r.entry)} → ${(r.hops || []).map(esc).join(" → ")}</span>` : `<span class="path">not reachable from an entrypoint</span>`;
    return `
      <tr class="clickable" data-i="${i}">
        <td><code>${esc(r.path)}:${esc(r.line)}</code><div class="muted">${esc(r.rule)}${r.cwe ? ` · ${esc(r.cwe)}` : ""}</div></td>
        <td class="${verdictClass(r.disposition)}">${esc(r.disposition)}</td>
        <td>${esc(r.confidence)}</td>
        <td>${path}</td>
        <td><span class="badge">${esc(r.coverage || "unknown")}</span></td>
      </tr>`;
  }).join("");
  $$("#review-table tbody tr").forEach((tr) => tr.onclick = () => toggleDetail(tr, rows[Number(tr.dataset.i)]));
}

function toggleDetail(tr, r) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("detailrow")) { next.remove(); return; }
  const detail = document.createElement("tr");
  detail.className = "detailrow";
  detail.innerHTML = `<td class="detail" colspan="5">
      <div><b>Why:</b> ${esc(r.rationale || "—")}</div>
      ${r.snippet ? `<pre class="snippet" style="max-height:240px;overflow:auto;margin:6px 0;padding:8px;background:rgba(128,128,128,.12);border-radius:6px">${esc(r.snippet)}</pre>` : ""}
      <div class="muted">language: ${esc(r.language || "?")} · evidence: ${(r.evidence || []).map(esc).join(", ") || "none"}</div>
      <div class="muted">entry: ${esc(r.entry || "—")} · hops: ${(r.hops || []).map(esc).join(" → ") || "—"} · coverage: ${esc(r.coverage || "—")}</div>
    </td>`;
  tr.after(detail);
}

$("#filter-verdict").onchange = renderTable;
$("#filter-search").oninput = renderTable;

$("#export-json").onclick = () => download("rewardaudit.json", JSON.stringify(RESULTS, null, 2), "application/json");
$("#export-csv").onclick = () => {
  const header = "path,line,language,rule,cwe,disposition,confidence,entry,hops,coverage,rationale";
  const lines = RESULTS.rows.map((r) => [
    r.path, r.line, r.language, r.rule, r.cwe, r.disposition, r.confidence, r.entry,
    (r.hops || []).join(" -> "), r.coverage, r.rationale,
  ].map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`).join(","));
  download("rewardaudit.csv", [header, ...lines].join("\n"), "text/csv");
};
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  URL.revokeObjectURL(url);
}

async function poll(jobId, progressId) {
  for (;;) {
    const job = await api(`/api/jobs/${jobId}`);
    setProgress(progressId, job.progress || 0, job.message || job.status);
    if (job.status === "done") return job.result;
    if (job.status === "error") throw new Error(job.error || "job failed");
    await new Promise((r) => setTimeout(r, 800));
  }
}
function setProgress(id, fraction, message) {
  const box = $(id);
  box.classList.toggle("hidden", fraction >= 1);
  box.querySelector(".bar").style.width = `${Math.round(fraction * 100)}%`;
  box.querySelector(".label").textContent = message || "";
}

// ── measure ─────────────────────────────────────────────────────────────
const DATASETS = [
  { id: "controls", title: "Java controls", desc: "Analyzer regression set. Expected: 12/18 vulnerable detected, 1/3 safe flagged." },
  { id: "python_pairs", title: "Python revision pairs", desc: "Four-way decomposition on hand-built vulnerable/fixed pairs." },
  { id: "javavfc_llm", title: "JavaVFC — LLM four-way", desc: "Does the LLM verdict track the fix? Needs a model (Local or Cloud)." },
  { id: "calibrate", title: "Calibration / FNR", desc: "Reliability, selective risk and false-negative rate. Needs a model." },
];

function renderMeasureCards() {
  $("#measure-cards").innerHTML = DATASETS.map((d) => `
    <div class="mcard">
      <h3>${esc(d.title)}</h3>
      <p>${esc(d.desc)}</p>
      <button class="btn" data-dataset="${esc(d.id)}">Run</button>
    </div>`).join("");
  $$("#measure-cards button").forEach((b) => b.onclick = () => runMeasure(b.dataset.dataset));
}

async function runMeasure(dataset) {
  $("#measure-results").innerHTML = "";
  try {
    const { id } = await api("/api/jobs", { kind: "measure", params: { dataset } });
    const result = await poll(id, "#measure-progress");
    $("#measure-results").innerHTML = renderMeasure(dataset, result);
  } catch (e) {
    $("#measure-results").innerHTML = `<div class="alert">${esc(e.message)}</div>`;
  }
}

function renderMeasure(dataset, r) {
  if (dataset === "controls") {
    const m = r.matrix;
    const rows = m.rows.map((row) => `<tr><td><code>${esc(row.file)}</code></td><td>${esc(row.expect)}</td>
      <td class="${row.detected === (row.expect === "vulnerable") ? "tp" : "fp"}">${row.detected ? "flagged" : "silent"}</td>
      <td class="muted">${(row.rules || []).map(esc).join(", ") || "—"}</td></tr>`).join("");
    return `<div class="card"><div class="stat-grid">
      ${stat("vulnerable detected", `${m.vulnerable_detected}/${m.vulnerable_total}`, "ok")}
      ${stat("safe flagged", `${m.safe_flagged}/${m.safe_total}`, m.safe_flagged ? "bad" : "ok")}
      ${stat("findings", m.findings_total)}</div>
      <table><thead><tr><th>control</th><th>expected</th><th>result</th><th>rules</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }
  if (dataset === "python_pairs" || dataset === "javavfc_llm") {
    const c = r.counts || {};
    return `<div class="card"><div class="stat-grid">
      ${stat("vuln_only (flip)", c.vuln_only, "ok")}${stat("both", c.both, c.both ? "warn" : "")}
      ${stat("neither", c.neither)}${stat("fixed_only", c.fixed_only)}
      ${stat("flip rate", `${Math.round((r.flip_rate || 0) * 100)}%`, "ok")}
      ${r.tokens_out !== undefined ? stat("tokens out", r.tokens_out) : ""}</div>
      <p class="hint">A flip (vuln_only) means the verdict moved with the fix — the strong signal. “both” means it flagged the construct before and after: not detection.</p></div>`;
  }
  if (dataset === "calibrate") {
    const m = r.metrics || {};
    const rel = (m.reliability || []).map((x) => `<tr><td>${esc(x.bin)}</td><td>${x.n}</td><td>${x.mean_confidence.toFixed(2)}</td><td>${x.accuracy.toFixed(2)}</td></tr>`).join("");
    const sel = (m.selective_risk || []).map((x) => `<tr><td>${x.threshold}</td><td>${Math.round(x.coverage * 100)}%</td><td>${x.n}</td><td>${x.risk === null ? "—" : x.risk.toFixed(2)}</td></tr>`).join("");
    return `<div class="card"><div class="stat-grid">
      ${stat("abstention", `${Math.round((m.abstention_rate || 0) * 100)}%`, "warn")}
      ${stat("detection", `${Math.round((m.detection_rate || 0) * 100)}%`, "ok")}
      ${stat("false negatives", `${Math.round((m.false_negative_rate || 0) * 100)}%`, "bad")}
      ${stat("fixed-side FP", `${Math.round((m.fixed_side_fp_rate || 0) * 100)}%`, m.fixed_side_fp_rate ? "bad" : "ok")}
      ${stat("accuracy", `${Math.round((m.accuracy || 0) * 100)}%`)}
      ${stat("ECE", (m.ece || 0).toFixed(3))}
      ${stat("tokens out", r.tokens_out || 0)}</div>
      <h3>Reliability</h3><table><thead><tr><th>confidence</th><th>n</th><th>mean conf</th><th>accuracy</th></tr></thead><tbody>${rel}</tbody></table>
      <h3 style="margin-top:14px">Selective risk</h3><table><thead><tr><th>threshold</th><th>coverage</th><th>n</th><th>risk</th></tr></thead><tbody>${sel}</tbody></table></div>`;
  }
  return `<div class="card"><pre>${esc(JSON.stringify(r, null, 2))}</pre></div>`;
}

// ── boot ────────────────────────────────────────────────────────────────
loadSettings().then(() => {
  renderMeasureCards();
  if (SETTINGS.backend !== "scripted" && SETTINGS.backend !== "local" || (SETTINGS.backend === "cloud" && !SETTINGS.api_key_set)) {
    openSetup(true); // nudge first-run setup when a model is required but missing
  }
}).catch((e) => toast(`Could not load settings: ${e.message}`, true));

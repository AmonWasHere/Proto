const $ = (sel) => document.querySelector(sel);
const api = async (path, body) => {
  const res = await fetch(path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {});
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  return res.json();
};

document.querySelectorAll(".tab").forEach((tab) => {
  tab.onclick = () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    $(`#tab-${tab.dataset.tab}`).classList.add("active");
  };
});

function setProgress(id, fraction, message) {
  const box = $(id);
  box.classList.toggle("hidden", fraction >= 1);
  box.querySelector(".bar").style.width = `${Math.round(fraction * 100)}%`;
  box.querySelector("span").textContent = message || "";
}

async function poll(jobId, progressId) {
  for (;;) {
    const job = await api(`/api/jobs/${jobId}`);
    setProgress(progressId, job.progress || 0, job.message || job.status);
    if (job.status === "done") { setProgress(progressId, 1); return job.result; }
    if (job.status === "error") { setProgress(progressId, 1); throw new Error(job.error); }
    await new Promise((r) => setTimeout(r, 800));
  }
}

function chip(label, value, cls = "") {
  return `<span class="chip ${cls}">${label} <b>${value}</b></span>`;
}

// ---------------- Review ----------------
$("#review-run").onclick = async () => {
  const button = $("#review-run");
  button.disabled = true;
  $("#review-summary").innerHTML = "";
  $("#review-results").innerHTML = "";
  try {
    const { id } = await api("/api/jobs", {
      kind: "review",
      params: {
        path: $("#review-path").value.trim(),
        verifier: $("#review-verifier").value,
        limit: Number($("#review-limit").value || 0),
      },
    });
    const result = await poll(id, "#review-progress");
    const s = result.summary;
    $("#review-summary").innerHTML = [
      chip("candidates", s.candidates),
      chip("true positive", s.true_positive, "tp"),
      chip("false positive", s.false_positive, "fp"),
      chip("abstained", s.unknown_risk, "ur"),
      chip("tokens in", s.tokens_in),
      chip("tokens out", s.tokens_out),
      chip("analyzer", `${s.analyzer} ${s.analyzer_version}`),
    ].join("");
    const rows = result.rows.map((r) => `
      <tr>
        <td><code>${r.path}:${r.line}</code></td>
        <td>${r.rule}</td>
        <td class="${r.disposition === "true_positive" ? "tp" : r.disposition === "false_positive" ? "fp" : "ur"}">${r.disposition}</td>
        <td>${r.confidence}</td>
        <td>${r.rationale}</td>
      </tr>`).join("");
    $("#review-results").innerHTML = rows
      ? `<table><thead><tr><th>location</th><th>rule</th><th>verdict</th><th>conf</th><th>rationale</th></tr></thead><tbody>${rows}</tbody></table>`
      : "<p class='hint'>No findings.</p>";
  } catch (e) {
    $("#review-summary").innerHTML = `<span class="chip">error: ${e.message}</span>`;
  } finally {
    button.disabled = false;
  }
};

// ---------------- Measure ----------------
$("#measure-run").onclick = async () => {
  const button = $("#measure-run");
  button.disabled = true;
  $("#measure-results").innerHTML = "";
  try {
    const { id } = await api("/api/jobs", {
      kind: "measure",
      params: {
        dataset: $("#measure-dataset").value,
        limit: Number($("#measure-limit").value || 0),
      },
    });
    const result = await poll(id, "#measure-progress");
    $("#measure-results").innerHTML = `<pre>${JSON.stringify(result, null, 2)}</pre>`;
  } catch (e) {
    $("#measure-results").innerHTML = `<span class="chip">error: ${e.message}</span>`;
  } finally {
    button.disabled = false;
  }
};

// ---------------- Settings ----------------
async function loadSettings() {
  const s = await api("/api/settings");
  $("#set-backend").value = s.backend;
  $("#set-base-url").value = s.base_url || "";
  $("#set-model").value = s.model || "";
  $("#set-no-thinking").checked = s.no_thinking;
  $("#set-cache").checked = s.cache;
  $("#set-status").innerHTML = [
    chip("api key", s.api_key_set ? "set" : "not set"),
    chip("opengrep", s.openai_ready ? "ready" : "missing"),
    chip("controls", s.datasets.controls ? "yes" : "no"),
    chip("python pairs", s.datasets.python_pairs ? "yes" : "no"),
    chip("javavfc", s.datasets.javavfc_pairs ? "yes" : "no"),
  ].join("");
}

$("#set-save").onclick = async () => {
  const payload = {
    backend: $("#set-backend").value,
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
    $("#set-status").innerHTML += chip("saved", "yes");
  } catch (e) {
    $("#set-status").innerHTML = `<span class="chip">error: ${e.message}</span>`;
  }
};

loadSettings().catch((e) => { $("#set-status").innerHTML = `<span class="chip">error: ${e.message}</span>`; });

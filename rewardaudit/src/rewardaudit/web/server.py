"""RewardAudit web application (stdlib only).

The operator starts it once; users open a browser and never touch a shell.

    python -m rewardaudit.web            # serves http://127.0.0.1:8765

Security posture:
* binds to 127.0.0.1 only;
* API keys live in the out-of-repo credential file (mode 600) and are never
  returned to the browser — only a boolean "is a key set" is;
* scanned code never leaves the machine unless the cloud backend is selected.
"""

from __future__ import annotations

import json
import os
import threading
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import config, graph, languages
from ..analyzers import AnalyzerError, Opengrep
from ..calibration import analyze
from ..controls import control_matrix, load_controls
from ..cpg import Cpg
from ..datasets import load_pairs
from ..decomposition import decompose
from ..e1 import collect_calibration, four_way_llm
from ..llm import build_backend
from ..review import partition_code_findings
from ..schema import Disposition
from ..verifiers.base import VerificationContext
from ..verifiers.llm_judge import LLMJudge

STATIC = Path(__file__).resolve().parent / "static"
ENV_FILE = Path(os.environ.get("REWARDAUDIT_ENV_FILE", "~/.config/rewardaudit/env")).expanduser()

JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()
SETTINGS: dict = {
    "backend": os.environ.get("REWARDAUDIT_BACKEND", "scripted"),
    "base_url": os.environ.get("REWARDAUDIT_LLM_BASE_URL", ""),
    "model": os.environ.get("REWARDAUDIT_LLM_MODEL", ""),
    "no_thinking": os.environ.get("REWARDAUDIT_NO_THINKING", "") in ("1", "true"),
    "cache": os.environ.get("REWARDAUDIT_LLM_CACHE", "") != "off",
}

BACKENDS = ["scripted", "mock", "local", "cloud"]


# --------------------------------------------------------------------------- #
# settings
# --------------------------------------------------------------------------- #
def _load_env_file() -> None:
    if not ENV_FILE.is_file():
        return
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


def _save_env_file() -> None:
    # Preserve an existing base URL / model when the incoming value is empty, so
    # switching to an offline backend does not wipe a configured cloud endpoint.
    base = SETTINGS["base_url"] or os.environ.get("REWARDAUDIT_LLM_BASE_URL", "") or (
        "http://localhost:11434/v1" if SETTINGS["backend"] == "local" else ""
    )
    model = SETTINGS["model"] or os.environ.get("REWARDAUDIT_LLM_MODEL", "") or (
        "qwen2.5-coder:7b" if SETTINGS["backend"] == "local" else ""
    )
    key = os.environ.get("REWARDAUDIT_LLM_API_KEY", "")
    lines = [
        "# Written by the RewardAudit web app. Never commit this file.",
        f"REWARDAUDIT_LLM_BASE_URL={base}",
        f"REWARDAUDIT_LLM_MODEL={model}",
        f"REWARDAUDIT_LLM_API_KEY={key}",
        f"REWARDAUDIT_NO_THINKING={'1' if SETTINGS['no_thinking'] else '0'}",
        f"REWARDAUDIT_LLM_CACHE={str(config.RUNS_DIR / 'llm_cache.jsonl') if SETTINGS['cache'] else 'off'}",
    ]
    ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    ENV_FILE.write_text("\n".join(lines) + "\n")
    os.chmod(ENV_FILE, 0o600)


def apply_env() -> None:
    if SETTINGS["base_url"]:
        os.environ["REWARDAUDIT_LLM_BASE_URL"] = SETTINGS["base_url"]
    if SETTINGS["model"]:
        os.environ["REWARDAUDIT_LLM_MODEL"] = SETTINGS["model"]
    if SETTINGS["backend"] == "local":
        if SETTINGS["base_url"]:
            os.environ["REWARDAUDIT_LOCAL_BASE_URL"] = SETTINGS["base_url"]
        # "auto"/empty -> let the backend recognize the served model itself.
        if SETTINGS["model"] and SETTINGS["model"].lower() not in ("auto", "offline"):
            os.environ["REWARDAUDIT_LOCAL_MODEL"] = SETTINGS["model"]
        else:
            os.environ.pop("REWARDAUDIT_LOCAL_MODEL", None)
    os.environ["REWARDAUDIT_NO_THINKING"] = "1" if SETTINGS["no_thinking"] else "0"
    os.environ["REWARDAUDIT_LLM_CACHE"] = (
        str(config.RUNS_DIR / "llm_cache.jsonl") if SETTINGS["cache"] else "off"
    )


def local_models() -> dict:
    """Auto-recognize the models served by the configured local endpoint."""
    apply_env()
    try:
        backend = build_backend("local", cache=False)
        return {
            "ok": True,
            "base_url": getattr(backend, "base_url", ""),
            "model": getattr(backend, "model", ""),
            "models": backend.list_models(),
        }
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def public_settings() -> dict:
    return {
        "backend": SETTINGS["backend"],
        "base_url": SETTINGS["base_url"] or os.environ.get("REWARDAUDIT_LLM_BASE_URL", ""),
        "model": SETTINGS["model"] or os.environ.get("REWARDAUDIT_LLM_MODEL", ""),
        "no_thinking": SETTINGS["no_thinking"],
        "cache": SETTINGS["cache"],
        "api_key_set": bool(os.environ.get("REWARDAUDIT_LLM_API_KEY")),
        "openai_ready": config.OPENGREP_BIN.is_file(),
        "datasets": {
            "controls": config.CONTROLS_DIR.is_dir(),
            "python_pairs": config.PYTHON_PAIRS.is_dir(),
            "javavfc_pairs": config.JAVAVFC_PAIRS.is_dir(),
        },
    }


# --------------------------------------------------------------------------- #
# jobs
# --------------------------------------------------------------------------- #
def _new_job(kind: str, params: dict) -> str:
    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        JOBS[job_id] = {"id": job_id, "kind": kind, "status": "running", "progress": 0.0,
                        "message": "starting", "params": params, "result": None, "error": None}
    threading.Thread(target=_run_job, args=(job_id, kind, params), daemon=True).start()
    return job_id


def _update(job_id: str, **fields) -> None:
    with _LOCK:
        JOBS[job_id].update(fields)


def _run_job(job_id: str, kind: str, params: dict) -> None:
    try:
        apply_env()
        if kind == "review":
            result = _job_review(job_id, params)
        elif kind == "audit":
            result = _job_audit(job_id, params)
        elif kind == "measure":
            result = _job_measure(job_id, params)
        else:
            raise ValueError(f"unknown job kind: {kind}")
        _update(job_id, status="done", progress=1.0, message="done", result=result)
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI
        _update(job_id, status="error", error=f"{type(exc).__name__}: {exc}",
                trace=traceback.format_exc()[-2000:])


#: Root the folder picker may browse. Defaults to the whole filesystem so users can
#: pick any project; set REWARDAUDIT_BROWSE_ROOT to confine it.
_env_root = os.environ.get("REWARDAUDIT_BROWSE_ROOT", "").strip()
BROWSE_ROOT = Path(_env_root).expanduser().resolve() if _env_root else Path("/").resolve()


def _browse(raw_path: str | None) -> dict:
    """List subdirectories for the folder picker (confined to BROWSE_ROOT)."""
    root = BROWSE_ROOT.resolve()
    unrestricted = root == Path("/")
    start = Path.home() if unrestricted else root
    requested = Path(raw_path).expanduser().resolve() if raw_path else start.resolve()
    if not unrestricted and root not in requested.parents and requested != root:
        requested = root
    entries = []
    try:
        for child in sorted(requested.iterdir(), key=lambda p: p.name.lower()):
            if child.is_dir() and not child.name.startswith("."):
                entries.append({"name": child.name, "path": str(child)})
    except OSError as exc:
        return {"error": str(exc), "path": str(requested), "root": str(root), "entries": []}
    parent = str(requested.parent) if requested != root else None
    return {
        "path": str(requested),
        "root": str(root),
        "home": str(Path.home()),
        "parent": parent,
        "entries": entries,
    }


def _functions(raw_path: str | None) -> dict:
    """List functions (for selective auditing) under a file or directory."""
    if not raw_path:
        return {"error": "no path"}
    target = Path(raw_path).expanduser()
    if not target.exists():
        return {"error": f"not found: {target}"}
    base = target if target.is_dir() else target.parent
    cpg = Cpg(base)
    if not cpg.available():
        return {"error": "tree-sitter is not installed"}
    out = []
    for lang, files in languages.detect(base).items():
        if not languages.registry()[lang].grammar:
            continue
        for p in sorted(files):
            rel = str(p.relative_to(base))
            try:
                fns = cpg.functions(rel)
            except Exception:  # noqa: BLE001 - unparseable file
                continue
            for fn in fns:
                out.append({"path": rel, "name": fn.name, "start_line": fn.start_line,
                            "end_line": fn.end_line, "lines": fn.lines})
    return {"root": str(base), "functions": out, "count": len(out)}


def _inspect(raw_path: str | None) -> dict:
    """Coverage + language mix for a directory, before running anything."""
    if not raw_path:
        return {"error": "no path"}
    target = Path(raw_path).expanduser()
    if not target.is_dir():
        return {"error": f"not a directory: {target}"}
    report = languages.coverage_report(target)
    return report


def _test_connection() -> dict:
    """One tiny call against the configured backend, to prove it works."""
    try:
        backend = build_backend(SETTINGS["backend"], cache=False, no_thinking=SETTINGS["no_thinking"])
        from ..llm.base import LLMRequest

        response = backend.complete(LLMRequest(system="Reply with JSON only.", user='Reply {"ok": true}', max_tokens=256))
        return {
            "ok": True,
            "backend": getattr(backend, "name", SETTINGS["backend"]),
            "model": getattr(backend, "model", ""),
            "reply": response.text[:120],
        }
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _job_audit(job_id: str, params: dict) -> dict:
    """LLM audit: pass whole functions to the model to find mistakes anywhere."""
    from ..audit import audit_codebase

    root = Path(params["path"]).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")
    backend_kind = params.get("backend") or SETTINGS["backend"]
    backend = build_backend(backend_kind, no_thinking=SETTINGS["no_thinking"])
    max_functions = int(params.get("max_functions") or 0)
    raw_sel = params.get("functions") or None
    selections = None
    if raw_sel:
        selections = {(s["path"], int(s["start_line"])) for s in raw_sel}

    def progress(path: str, name: str, index: int) -> None:
        _update(job_id, message=f"audited {index}: {path}::{name}",
                progress=min(0.95, 0.05 + index * 0.01))

    _update(job_id, message="auditing functions", progress=0.05)
    report = audit_codebase(
        root, backend, max_functions=max_functions, selections=selections, gate=True, progress=progress
    )
    return report.to_dict()


def _job_review(job_id: str, params: dict) -> dict:
    root = Path(params["path"]).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")

    coverage = languages.coverage_report(root)
    rules = Path(params["rules"]).resolve() if params.get("rules") else languages.rules_for(root)
    if not rules:
        raise AnalyzerError(
            "no ruleset for any language present; unchecked languages: "
            + ", ".join(coverage["unchecked_languages"] or ["(none)"])
        )
    analyzer = Opengrep(config.OPENGREP_BIN, rules)
    if not analyzer.available():
        raise AnalyzerError(f"opengrep not available at {config.OPENGREP_BIN}")
    _update(job_id, message=f"scanning ({len(rules)} ruleset(s))", progress=0.05)
    scan = analyzer.scan(root)

    limit = int(params.get("limit") or 0)
    code, noncode = partition_code_findings(scan.findings)
    findings = code[: limit or None]

    # Path candidates give each finding an entry -> ... -> sink traversal and a
    # per-path coverage label (its least-covered hop).
    _update(job_id, message="building codebase graph", progress=0.1)
    paths = {row["finding"]: row for row in graph.path_candidates(root, findings)}

    verifier = params.get("verifier", "llm")
    backend = build_backend(SETTINGS["backend"], no_thinking=SETTINGS["no_thinking"])
    judge = LLMJudge(gate_evidence=verifier != "llm_ungated")
    ctx = VerificationContext(root, Cpg(root), backend)

    rows = []
    total = len(findings) or 1
    for index, finding in enumerate(findings, start=1):
        verdict = judge.verify(finding, ctx)
        path_row = paths.get(finding.id, {})
        hops = path_row.get("hops") or []
        try:
            snippet = ctx.cpg.context_slice(finding.location.path, finding.location.start_line, max_chars=1600)
        except Exception:  # noqa: BLE001 - snippet is best-effort
            snippet = ""
        rows.append(
            {
                "path": finding.location.path,
                "line": finding.location.start_line,
                "rule": finding.rule,
                "cwe": finding.cwes[0] if finding.cwes else "",
                "language": path_row.get("language") or "",
                "disposition": verdict.disposition.value,
                "confidence": round(verdict.confidence, 3),
                "rationale": verdict.rationale,
                "evidence": list(verdict.evidence_refs),
                "entry": path_row.get("entry"),
                "hops": hops,
                "reachable": bool(path_row.get("reachable")),
                "coverage": path_row.get("coverage", "unknown"),
                "snippet": snippet,
            }
        )
        _update(job_id, message=f"verified {index}/{len(findings)}", progress=0.15 + 0.85 * index / total)

    summary = {
        "analyzer": analyzer.name,
        "analyzer_version": scan.version,
        "rulesets": [Path(r).name for r in rules],
        "candidates": len(findings),
        "skipped_noncode": len(noncode),
        "skipped_paths": sorted({f.location.path for f in noncode})[:10],
        "true_positive": sum(r["disposition"] == "true_positive" for r in rows),
        "false_positive": sum(r["disposition"] == "false_positive" for r in rows),
        "unknown_risk": sum(r["disposition"] == "unknown_risk" for r in rows),
        "reachable": sum(r["reachable"] for r in rows),
        "tokens_in": judge.tokens_in,
        "tokens_out": judge.tokens_out,
        "coverage": coverage,
    }
    stats = backend.stats() if hasattr(backend, "stats") else {}
    return {"summary": summary, "rows": rows, "cache": stats}


def _job_measure(job_id: str, params: dict) -> dict:
    dataset = params.get("dataset", "controls")
    limit = int(params.get("limit") or 0)
    _update(job_id, message=f"measuring {dataset}", progress=0.2)

    if dataset == "controls":
        analyzer = Opengrep(config.OPENGREP_BIN, config.JAVA_RULES)
        scan = analyzer.scan(config.CONTROLS_DIR)
        matrix = control_matrix(load_controls(config.CONTROLS_DIR), scan.findings)
        return {"kind": "controls", "matrix": matrix}

    if dataset == "python_pairs":
        analyzer = Opengrep(config.OPENGREP_BIN, config.PYTHON_RULES)
        scan = analyzer.scan(config.PYTHON_PAIRS)
        report = decompose(load_pairs(config.PYTHON_PAIRS / "manifest.json"), scan.findings)
        return {"kind": "python_pairs", "counts": report.counts(),
                "flip_rate": report.flip_rate, "naive_coverage": report.naive_coverage}

    if dataset == "javavfc_llm":
        pairs = load_pairs(config.JAVAVFC_PAIRS / "manifest.json")
        if limit:
            pairs = pairs[:limit]
        backend = build_backend(SETTINGS["backend"], no_thinking=SETTINGS["no_thinking"])
        judge = LLMJudge()
        ctx = VerificationContext(config.JAVAVFC_PAIRS.resolve(), Cpg(config.JAVAVFC_PAIRS), backend)
        result = four_way_llm(pairs, ctx, judge)
        return {"kind": "javavfc_llm", "counts": result.report.counts(),
                "flip_rate": result.report.flip_rate,
                "tokens_in": judge.tokens_in, "tokens_out": judge.tokens_out}

    if dataset == "calibrate":
        pairs = load_pairs(config.JAVAVFC_PAIRS / "manifest.json")
        if limit:
            pairs = pairs[:limit]
        backend = build_backend(SETTINGS["backend"], no_thinking=SETTINGS["no_thinking"])
        judge = LLMJudge()
        ctx = VerificationContext(config.JAVAVFC_PAIRS.resolve(), Cpg(config.JAVAVFC_PAIRS), backend)
        points, abstained = collect_calibration(pairs, ctx, judge)
        return {"kind": "calibrate", "metrics": analyze(points, abstained=abstained),
                "tokens_in": judge.tokens_in, "tokens_out": judge.tokens_out}

    raise ValueError(f"unknown dataset: {dataset}")


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
CONTENT_TYPES = {".html": "text/html", ".js": "text/javascript", ".css": "text/css"}


class Handler(BaseHTTPRequestHandler):
    server_version = "RewardAudit"

    def log_message(self, fmt, *args):  # quieter
        pass

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._send(code, json.dumps(payload).encode(), "application/json")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode())
        except json.JSONDecodeError:
            return {}

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path in ("/", "/index.html"):
            return self._serve_static("index.html")
        if path.startswith("/static/"):
            return self._serve_static(path.split("/", 2)[-1])
        if path == "/api/settings":
            return self._json(200, public_settings())
        if path == "/api/backends":
            return self._json(200, {"backends": BACKENDS})
        if path == "/api/local/models":
            return self._json(200, local_models())
        if path == "/api/browse":
            return self._json(200, _browse((query.get("path") or [None])[0]))
        if path == "/api/inspect":
            return self._json(200, _inspect((query.get("path") or [None])[0]))
        if path == "/api/functions":
            return self._json(200, _functions((query.get("path") or [None])[0]))
        if path.startswith("/api/jobs/"):
            job_id = path.rsplit("/", 1)[-1]
            with _LOCK:
                job = JOBS.get(job_id)
            if job is None:
                return self._json(404, {"error": "no such job"})
            return self._json(200, {k: v for k, v in job.items() if k != "trace"})
        return self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        path = urlparse(self.path).path
        body = self._body()
        if path == "/api/settings":
            if "api_key" in body and body["api_key"]:
                os.environ["REWARDAUDIT_LLM_API_KEY"] = body.pop("api_key")
            for key in ("backend", "base_url", "model", "no_thinking", "cache"):
                if key in body:
                    SETTINGS[key] = body[key]
            apply_env()
            try:
                _save_env_file()
                saved = True
            except OSError:
                saved = False
            payload = public_settings()
            payload["saved"] = saved
            return self._json(200, payload)
        if path == "/api/jobs":
            kind = body.get("kind", "review")
            params = body.get("params", {})
            job_id = _new_job(kind, params)
            return self._json(200, {"id": job_id})
        if path == "/api/test":
            return self._json(200, _test_connection())
        return self._json(404, {"error": "not found"})

    def _serve_static(self, name: str) -> None:
        target = (STATIC / name).resolve()
        if not str(target).startswith(str(STATIC)) or not target.is_file():
            return self._json(404, {"error": "not found"})
        self._send(200, target.read_bytes(), CONTENT_TYPES.get(target.suffix, "application/octet-stream"))


def serve(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    _load_env_file()
    apply_env()
    httpd = ThreadingHTTPServer((host, port), Handler)
    return httpd


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="rewardaudit.web")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    httpd = serve(args.host, args.port)
    print(f"RewardAudit running at http://{args.host}:{args.port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

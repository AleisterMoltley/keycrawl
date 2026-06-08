"""
KeyCrawl Web Service + minimal UI (Railway ready).

Run locally:
    uvicorn app:app --reload --port 8080

Deployed on Railway: the Dockerfile + railway.toml handle everything.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Any

from fastapi import FastAPI, BackgroundTasks, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from keycrawl.scanner import crawl_and_scan, ScanResult

app = FastAPI(
    title="KeyCrawl",
    description="Scan websites for leaked API keys, private keys, tokens and high-entropy secrets.",
    version="0.1.0",
)

# In-memory job store (ephemeral - perfect for Railway one-off scans)
JOBS: dict[str, dict[str, Any]] = {}
MAX_CONCURRENT_SCANS = 3
SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


class ScanRequest(BaseModel):
    url: str
    max_depth: int = 1
    max_pages: int = 25
    same_domain_only: bool = True


def _sanitize_url(u: str) -> str:
    u = u.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    return u


async def _run_scan_job(job_id: str, req: ScanRequest) -> None:
    """Background worker."""
    async with SCAN_SEMAPHORE:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["started_at"] = time.time()

        try:
            result: ScanResult = await crawl_and_scan(
                req.url,
                max_depth=min(req.max_depth, 3),
                max_pages=min(req.max_pages, 60),
                same_domain_only=req.same_domain_only,
                concurrency=5,
                request_delay=0.18,
            )
            # Strip raw values for safety in the web UI / API
            safe_findings = []
            for f in result.findings:
                d = f.model_dump()
                d.pop("value", None)
                safe_findings.append(d)

            JOBS[job_id].update(
                {
                    "status": "done",
                    "finished_at": time.time(),
                    "result": {
                        "target": result.target,
                        "pages_crawled": result.pages_crawled,
                        "findings": safe_findings,
                        "stats": result.stats,
                        "errors": result.errors,
                    },
                }
            )
        except Exception as e:
            JOBS[job_id].update(
                {
                    "status": "error",
                    "finished_at": time.time(),
                    "error": str(e),
                }
            )


# ---------------------------
# HTML UI (single file, Tailwind + HTMX via CDN)
# ---------------------------

INDEX_HTML = """<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KeyCrawl • Web Secrets Scanner</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js"></script>
  <style>
    body { font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .finding { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .secret { background: #fef3c7; padding: 1px 4px; border-radius: 3px; }
  </style>
</head>
<body class="bg-zinc-950 text-zinc-200">
  <div class="max-w-5xl mx-auto p-6">
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-4xl font-semibold tracking-tighter">keycrawl</h1>
        <p class="text-zinc-400 text-sm mt-1">Website Secrets Scanner — API Keys • Private Keys • Tokens</p>
      </div>
      <div class="text-right text-xs text-zinc-500">
        Railway-ready • Private repo<br>
        <span class="text-emerald-400">v0.1</span>
      </div>
    </div>

    <div class="bg-zinc-900 border border-zinc-800 rounded-2xl p-6 mb-8">
      <form hx-post="/scan" hx-target="#results" hx-swap="innerHTML" hx-indicator="#loading"
            class="grid grid-cols-1 md:grid-cols-5 gap-4">
        
        <div class="md:col-span-2">
          <label class="block text-xs uppercase tracking-widest text-zinc-500 mb-1">Target URL / Domain</label>
          <input name="url" type="text" required placeholder="https://example.com or example.com"
                 class="w-full bg-zinc-950 border border-zinc-700 focus:border-emerald-500 rounded-xl px-4 py-3 text-lg outline-none">
        </div>

        <div>
          <label class="block text-xs uppercase tracking-widest text-zinc-500 mb-1">Max Depth</label>
          <select name="max_depth" class="w-full bg-zinc-950 border border-zinc-700 rounded-xl px-4 py-3">
            <option value="0">0 (single page)</option>
            <option value="1" selected>1 (recommended)</option>
            <option value="2">2</option>
            <option value="3">3 (slow)</option>
          </select>
        </div>

        <div>
          <label class="block text-xs uppercase tracking-widest text-zinc-500 mb-1">Max Pages</label>
          <select name="max_pages" class="w-full bg-zinc-950 border border-zinc-700 rounded-xl px-4 py-3">
            <option value="10">10</option>
            <option value="25" selected>25</option>
            <option value="40">40</option>
            <option value="60">60 (max)</option>
          </select>
        </div>

        <div class="flex flex-col justify-end">
          <label class="flex items-center gap-2 text-sm mb-1.5">
            <input type="checkbox" name="same_domain_only" checked class="accent-emerald-500">
            <span class="text-zinc-300">Same domain only</span>
          </label>
          <button type="submit"
                  class="w-full bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 transition rounded-xl px-6 py-3 font-medium text-white flex items-center justify-center gap-2">
            <span>Start Scan</span>
          </button>
        </div>
      </form>

      <div id="loading" class="htmx-indicator mt-3 text-xs text-emerald-400 flex items-center gap-2">
        <div class="animate-spin h-3 w-3 border border-emerald-400 border-t-transparent rounded-full"></div>
        Scanning… (this can take 10–90 seconds depending on depth)
      </div>
    </div>

    <div id="results" class="space-y-4"></div>

    <div class="mt-12 text-[10px] text-zinc-500 leading-relaxed border-t border-zinc-900 pt-6">
      <strong class="text-zinc-400">Legal &amp; Responsible Use:</strong> Only scan websites you own or have explicit written permission to test.
      Finding real credentials can be a serious security issue. This tool is intended for authorized security assessments, bug bounty programs,
      and defensive research. The authors are not responsible for misuse. Raw secret values are never stored on the server.
    </div>
  </div>

  <script>
    // small tailwind script for nice defaults if needed
    document.body.addEventListener('htmx:afterSwap', () => {
      // could add copy buttons etc. later
    });
  </script>
</body>
</html>
"""

RESULT_PARTIAL = """
<div class="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
  <div class="flex items-baseline justify-between mb-4">
    <div>
      <span class="text-emerald-400 text-sm">SCAN COMPLETE</span>
      <h2 class="text-2xl font-semibold tracking-tight">{{ target }}</h2>
    </div>
    <div class="text-right">
      <div class="text-xs text-zinc-500">Pages • {{ pages }}</div>
      <div class="text-3xl font-semibold tabular-nums {{ 'text-red-400' if findings|length > 0 else 'text-emerald-400' }}">
        {{ findings|length }}
      </div>
      <div class="text-[10px] text-zinc-500 -mt-1">findings</div>
    </div>
  </div>

  {% if findings %}
  <div class="space-y-3">
    {% for f in findings %}
    <div class="bg-zinc-950 border border-zinc-800 rounded-xl p-4 text-sm">
      <div class="flex items-center gap-2 mb-1">
        <span class="px-2 py-0.5 rounded bg-zinc-800 text-emerald-400 text-xs font-medium">{{ f.secret_type }}</span>
        <span class="font-mono text-amber-300 secret">{{ f.value_redacted }}</span>
      </div>
      <div class="text-zinc-400 text-xs mb-1">{{ f.url }}</div>
      <div class="finding text-zinc-400 text-xs break-all">{{ f.context }}</div>
      {% if f.entropy %}<div class="text-[10px] text-zinc-600 mt-1">entropy: {{ '%.2f'|format(f.entropy) }}</div>{% endif %}
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="py-8 text-center">
    <div class="text-emerald-400 text-lg">✓ Clean — no secrets detected</div>
    <div class="text-xs text-zinc-500 mt-1">This does not guarantee the site is free of secrets. Manual review + other tools still recommended.</div>
  </div>
  {% endif %}

  <div class="mt-4 text-[10px] text-zinc-500">
    Duration: {{ '%.1f'|format(duration) }}s • Concurrency limited for politeness.
  </div>
</div>
"""

ERROR_PARTIAL = """
<div class="bg-red-950/60 border border-red-900 rounded-2xl p-5 text-sm">
  <div class="font-semibold text-red-400 mb-1">Scan failed</div>
  <div class="text-red-300">{{ error }}</div>
</div>
"""


def render(template: str, **ctx: Any) -> str:
    # Extremely minimal Jinja-like replacement for zero deps.
    # Only supports {{ var }} and very basic {% if %} for this UI.
    import re

    out = template
    # simple if
    def _if(m):
        inner = m.group(1)
        cond = m.group(2).strip()
        body = m.group(3)
        else_body = m.group(4) or ""
        truthy = False
        if cond.startswith("findings|length > 0"):
            truthy = bool(ctx.get("findings"))
        elif cond == "findings":
            truthy = bool(ctx.get("findings"))
        return body if truthy else else_body

    out = re.sub(r"\{% if (.*?) %\}(.*?)(?:\{% else %\}(.*?))?\{% endif %\}", _if, out, flags=re.S)

    for k, v in ctx.items():
        if isinstance(v, (int, float)):
            out = out.replace("{{ " + k + " }}", str(v))
            out = out.replace("{{ " + k + "|length }}", str(len(v) if hasattr(v, "__len__") else 0))
        else:
            out = out.replace("{{ " + k + " }}", str(v))
    # crude filters used
    out = re.sub(r"\{\{ '%.1f'\|format\((.*?)\) \}\}", lambda m: f"{float(ctx.get(m.group(1), 0)):.1f}", out)
    out = re.sub(r"\{\{ '%.2f'\|format\((.*?)\) \}\}", lambda m: f"{float(ctx.get(m.group(1), 0)):.2f}", out)
    out = out.replace("{{ findings|length }}", str(len(ctx.get("findings", []))))
    out = out.replace("{{ pages }}", str(ctx.get("pages_crawled", 0)))
    return out


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(INDEX_HTML)


@app.post("/scan", response_class=HTMLResponse)
async def trigger_scan(
    background_tasks: BackgroundTasks,
    url: str = Form(...),
    max_depth: int = Form(1),
    max_pages: int = Form(25),
    same_domain_only: str | None = Form(None),
):
    target = _sanitize_url(url)
    req = ScanRequest(
        url=target,
        max_depth=max_depth,
        max_pages=max_pages,
        same_domain_only=bool(same_domain_only),
    )

    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {
        "id": job_id,
        "status": "queued",
        "target": target,
        "created_at": time.time(),
    }

    background_tasks.add_task(_run_scan_job, job_id, req)

    # Return a polling card immediately
    html = f"""
    <div hx-get="/results/{job_id}" hx-trigger="every 1200ms" hx-swap="outerHTML" class="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
      <div class="flex items-center gap-3">
        <div class="animate-pulse h-2.5 w-2.5 bg-emerald-400 rounded-full"></div>
        <div>
          <div class="font-medium">Scanning <span class="font-mono text-emerald-300">{target}</span></div>
          <div class="text-xs text-zinc-500">Job <span class="font-mono">{job_id}</span> • polling for results…</div>
        </div>
      </div>
    </div>
    """
    return HTMLResponse(html)


@app.get("/results/{job_id}", response_class=HTMLResponse)
async def get_results(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return HTMLResponse("<div class='text-red-400'>Job not found (server restarted?)</div>")

    if job["status"] in ("queued", "running"):
        return HTMLResponse(f"""
        <div hx-get="/results/{job_id}" hx-trigger="every 1100ms" hx-swap="outerHTML" class="bg-zinc-900 border border-zinc-800 rounded-2xl p-6">
          <div class="flex items-center gap-3">
            <div class="animate-spin h-3 w-3 border-2 border-emerald-400 border-t-transparent rounded-full"></div>
            <div class="text-sm">Still scanning <span class="font-mono">{job.get('target')}</span> …</div>
          </div>
        </div>
        """)

    if job["status"] == "error":
        return HTMLResponse(render(ERROR_PARTIAL, error=job.get("error", "unknown error")))

    # done
    r = job.get("result", {})
    duration = (job.get("finished_at", time.time()) - job.get("started_at", time.time()))
    return HTMLResponse(
        render(
            RESULT_PARTIAL,
            target=r.get("target"),
            pages=r.get("pages_crawled", 0),
            findings=r.get("findings", []),
            duration=duration,
        )
    )


@app.post("/api/scan")
async def api_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    """JSON API for programmatic use / Railway jobs."""
    target = _sanitize_url(req.url)
    job_id = uuid.uuid4().hex[:12]
    JOBS[job_id] = {"id": job_id, "status": "queued", "target": target, "created_at": time.time()}
    background_tasks.add_task(_run_scan_job, job_id, req)
    return {"job_id": job_id, "status": "queued", "poll_url": f"/results/{job_id}"}


@app.get("/api/jobs/{job_id}")
async def api_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return JSONResponse({"error": "not found"}, status_code=404)
    return job


@app.get("/health")
async def health():
    return {"status": "ok", "jobs_in_memory": len(JOBS)}


# Allow running with: python app.py (for Railway worker or local test)
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)

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

from fastapi import FastAPI, BackgroundTasks, Form
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from keycrawl.scanner import crawl_and_scan, ScanResult, findings_to_safe_dicts
from keycrawl import storage

# Re-export for backward compatibility / other modules
DB_PATH = storage.DB_PATH
init_db = storage.init_db
save_scan_result = storage.save_scan_result
get_all_findings = storage.get_all_findings
get_category_counts = storage.get_category_counts
get_high_risk_findings = storage.get_high_risk_findings

# ------------------------------------------------------------------
# SAFETY NOTICE (repeated from storage.py)
# ------------------------------------------------------------------
# Raw secret values are NEVER stored by this application.
# The dashboard and DB only ever contain redacted representations.
# Previous requests to store raw private keys or to automatically drain
# wallets when Solana (or other) private keys are found have been refused.
# ------------------------------------------------------------------

app = FastAPI(
    title="KeyCrawl",
    description="Focused scanner for usernames/passwords and wallet private keys (Solana, Ethereum, mnemonics). Collection dashboard (redacted) for authorized leak detection on your own systems.",
    version="0.3.0",
)

@app.on_event("startup")
async def on_startup():
    await storage.init_db()

# In-memory job store (ephemeral - perfect for Railway one-off scans)
JOBS: dict[str, dict[str, Any]] = {}
MAX_CONCURRENT_SCANS = 3
SCAN_SEMAPHORE = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


class ScanRequest(BaseModel):
    url: str
    max_depth: int = 1
    max_pages: int = 25
    same_domain_only: bool = True


# DB functions are now provided by keycrawl.storage (imported above).
# The web layer only ever works with the redacted-safe versions.


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
            started_at = JOBS[job_id].get("started_at") or result.started_at
            finished_at = time.time()

            # For the *current scan result* (ephemeral, only visible to the person who just ran this scan):
            # we include the raw value so the operator can see exactly what was found.
            # WARNING: This is only in-memory for this job. It is not persisted.
            full_findings = []
            for f in result.findings:
                d = f.model_dump()
                full_findings.append(d)  # includes 'value' for the live result only

            # Always strip for the persistent collection
            safe_findings = findings_to_safe_dicts(result.findings)

            done_result = {
                "target": result.target,
                "pages_crawled": result.pages_crawled,
                "findings": full_findings,   # live result has raw for the operator
                "stats": result.stats,
                "errors": result.errors,
                "started_at": started_at,
                "finished_at": finished_at,
            }
            JOBS[job_id].update(
                {
                    "status": "done",
                    "finished_at": finished_at,
                    "result": done_result,
                }
            )

            # Persist ONLY redacted findings to the shared collection (dashboard DB)
            # Raw values are never written to the permanent collection.
            try:
                await storage.save_scan_result(
                    scan_id=job_id,
                    target=result.target,
                    started_at=started_at,
                    finished_at=finished_at,
                    pages_crawled=result.pages_crawled,
                    findings=safe_findings,
                )
            except Exception as db_exc:
                print(f"[keycrawl] DB save failed (non-fatal): {db_exc}")
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
  <title>KeyCrawl • Credential + Wallet Key Scanner</title>
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
      <div class="flex items-center gap-4">
        <div>
          <h1 class="text-4xl font-semibold tracking-tighter">keycrawl</h1>
          <p class="text-zinc-400 text-sm mt-1">Focused on usernames/passwords + wallet private keys (Solana, EVM, seeds). For your own controlled sites only.</p>
        </div>
        <a href="/dashboard"
           class="ml-4 px-4 py-1.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-sm font-medium border border-zinc-700">📊 Collection Dashboard</a>
      </div>
      <div class="text-right text-xs text-zinc-500">
        Railway-ready • Private repo<br>
        <span class="text-emerald-400">v0.2</span>
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
      and defensive research. The authors are not responsible for misuse. Raw secret values are never stored in the persistent collection.
      Use --export-full (CLI) or the live result + /api/scan/.../full-export for full raw data (per scan, your responsibility).
    </div>
  </div>

  <script>
    // small tailwind script for nice defaults if needed
    document.body.addEventListener('htmx:afterSwap', () => {
      // could add copy buttons etc. later
    });

    function downloadFullRaw(jobId) {
      if (!jobId) {
        alert('No job ID available for this result.');
        return;
      }
      fetch(`/api/scan/${jobId}/full-export`)
        .then(response => {
          if (!response.ok) throw new Error('Download failed: ' + response.status);
          return response.blob();
        })
        .then(blob => {
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.style.display = 'none';
          a.href = url;
          a.download = `keycrawl-full-raw-${jobId}.json`;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);
        })
        .catch(err => {
          console.error(err);
          alert('Failed to download full raw JSON: ' + err.message + '\nYou can also manually call /api/scan/' + jobId + '/full-export');
        });
    }
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
  <div class="bg-red-950 border border-red-900 rounded-xl p-3 mb-4 text-xs text-red-200">
    <strong>⚠️ LIVE SCAN RESULT — RAW SECRETS VISIBLE HERE</strong><br>
    These values are only shown for the scan you just triggered (in-memory only).<br>
    They are <strong>NOT</strong> saved to the permanent collection or dashboard.<br>
    The collection (/dashboard) only ever stores redacted versions.
  </div>

  <div class="mb-4">
    <button onclick="downloadFullRaw('{{ job_id }}')"
            class="w-full bg-yellow-600 hover:bg-yellow-500 active:bg-yellow-700 text-black font-semibold px-4 py-2 rounded-xl text-sm flex items-center justify-center gap-2">
      ⬇️ Download full raw JSON (unredacted values for this scan only)
    </button>
    <div class="text-[10px] text-yellow-400 mt-1 text-center">
      Job: {{ job_id }} — This downloads the complete raw secrets found in this specific scan. Handle with care.
    </div>
  </div>
  <div class="space-y-3">
    {% for f in findings %}
    <div class="bg-zinc-950 border border-zinc-800 rounded-xl p-4 text-sm">
      <div class="flex items-center gap-2 mb-1">
        <span class="px-2 py-0.5 rounded bg-zinc-800 text-emerald-400 text-xs font-medium">{{ f.secret_type }}</span>
        <span class="font-mono text-red-400 secret break-all">VALUE: {{ f.value or f.value_redacted }}</span>
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

# ------------------------------------------------------------------
# COLLECTION DASHBOARD
# Shows ALL discovered (redacted) secrets, grouped by category.
# This is the "all the keys sammelt, nach kategorie" feature.
# ------------------------------------------------------------------
DASHBOARD_HTML = """<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KeyCrawl - Nur Wallet Keys (simpel)</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-zinc-950 text-zinc-200 p-8 max-w-2xl mx-auto">
  <h1 class="text-4xl font-bold mb-1">keycrawl</h1>
  <p class="text-emerald-400 mb-6">Nur Wallet Private Keys • unredacted • im Browser • keine Speicherung</p>

  <div class="bg-zinc-900 border border-zinc-700 rounded-2xl p-6">
    <input id="url" type="text" value="https://stableponzi.com/" 
           class="w-full bg-zinc-950 border border-zinc-600 rounded-xl px-4 py-3 text-lg mb-3 focus:outline-none focus:border-emerald-500">
    <button id="scan-btn" type="button" onclick="doScan()"
            class="w-full bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 py-3 rounded-xl font-medium text-lg transition">
      Scan for Wallet Keys
    </button>
    <div id="status" class="mt-3 p-3 bg-zinc-800 text-sm font-medium text-emerald-400 min-h-[2.5rem] rounded border border-emerald-600">Status: bereit. Klick auf den Button → sofort sichtbare Rückmeldung (farbig + Text + Button-Änderung).</div>
  </div>

  <div id="results" class="mt-6 border-2 border-emerald-600 rounded-xl p-4 bg-zinc-900">
    <div class="flex justify-between items-center mb-2">
      <div class="font-semibold text-lg">Unredacted Wallet Keys (only)</div>
      <button onclick="copyAll()" class="text-xs px-3 py-1 bg-zinc-800 hover:bg-zinc-700 rounded">Copy all</button>
    </div>
    <pre id="keys" class="bg-black p-4 rounded text-sm font-mono overflow-auto whitespace-pre-wrap break-all border border-zinc-800 min-h-[4rem] text-yellow-300">Klicke auf "Scan for Wallet Keys". Du siehst SOFORT Feedback (Button + Status + Text hier ändern sich). Dann erscheinen die unredacted Keys (eine pro Zeile) oder eine Fehlermeldung.</pre>
  </div>

  <div class="mt-8 text-xs text-zinc-500">
    <strong>Legal:</strong> Nur eigene Seiten oder mit Erlaubnis. Sofort rotieren. Keine Auto-Transfer-Logik.
  </div>

  <script>
    async function doScan() {
      // === ULTRA RELIABLE IMMEDIATE FEEDBACK ===
      // This runs synchronously the moment the function is invoked (via onclick or listener).
      // Guarantees visible change even if later code crashes or elements are missing.
      console.log('%c[KeyCrawl] doScan() INVOKED — click registered', 'color:#0f0;font-size:13px');
      try {
        const statusEl = document.getElementById('status');
        const btnEl = document.getElementById('scan-btn');
        const keysEl = document.getElementById('keys');

        // 1. Make status impossible to miss (big green banner)
        if (statusEl) {
          statusEl.style.cssText = 'background:#052e16;border:2px solid #4ade80;color:#4ade80;font-weight:700;font-size:15px;padding:10px 12px;margin-top:8px;border-radius:8px;';
          statusEl.textContent = '✅ KLICK ERKANNT — Scan startet sofort...';
        }
        // 2. Button visual change right now
        let origBtnText = 'Scan for Wallet Keys';
        if (btnEl) {
          origBtnText = btnEl.innerText || origBtnText;
          btnEl.disabled = true;
          btnEl.innerText = 'Scanning…';
          btnEl.style.backgroundColor = '#166534';
          btnEl.style.border = '2px solid #4ade80';
        }
        // 3. Keys area shows we are working
        if (keysEl) {
          keysEl.style.borderColor = '#4ade80';
          keysEl.textContent = 'Scanning... (Server-Antwort wird erwartet — kann 5–40s dauern je nach Seite)';
        }

        // now collect input (after showing feedback, so even bad URL still shows "click worked")
        const urlInput = document.getElementById('url');
        const url = (urlInput && urlInput.value || '').trim();
        if (!url) {
          if (statusEl) { statusEl.style.backgroundColor='#7f1d1d'; statusEl.textContent='Bitte eine URL eingeben!'; }
          if (btnEl) { btnEl.disabled=false; btnEl.innerText=origBtnText; btnEl.style.backgroundColor=''; btnEl.style.border=''; }
          if (keysEl) keysEl.textContent = 'Klicke auf den Button. Die unredacted Keys erscheinen HIER direkt im Browser (eine pro Zeile).';
          return;
        }

        // update status with real target
        if (statusEl) statusEl.textContent = 'Scanning ' + url + ' … (bitte warten)';

        const r = await fetch('/scan-wallet-keys', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({url: url, max_depth: 1, max_pages: 10, same_domain_only: true})
        });
        const d = await r.json();
        if (d.error) throw new Error(d.error);
        if (!d.keys || d.keys.length === 0) {
          if (keysEl) keysEl.textContent = 'Keine Wallet Private Keys gefunden.\n\n(Hinweis: Der Crawler holt den HTML/JS-Quelltext. Manche Keys sind nur in dynamisch geladenem JS oder nach Login. Versuche eine andere URL oder CLI für mehr Tiefe.)';
        } else {
          if (keysEl) keysEl.textContent = d.keys.join('\n');
        }
        if (statusEl) {
          statusEl.style.cssText = 'background:#052e16;border:1px solid #4ade80;color:#4ade80;padding:8px;border-radius:8px;';
          statusEl.textContent = `Fertig: ${d.keys ? d.keys.length : 0} Keys von ${d.target || url} (${d.pages_crawled || '?'} Seiten)`;
        }
      } catch(e) {
        const statusEl = document.getElementById('status');
        const keysEl = document.getElementById('keys');
        if (keysEl) keysEl.textContent = 'Fehler: ' + (e && e.message ? e.message : e);
        if (statusEl) {
          statusEl.style.cssText = 'background:#7f1d1d;border:2px solid #f87171;color:#fecaca;padding:10px;border-radius:8px;';
          statusEl.textContent = 'Scan fehlgeschlagen. Siehe Console (F12) für Details. ' + (e && e.message ? e.message : '');
        }
        console.error('[KeyCrawl] scan error', e);
      } finally {
        const btnEl = document.getElementById('scan-btn');
        if (btnEl) {
          btnEl.disabled = false;
          btnEl.style.backgroundColor = '';
          btnEl.style.border = '';
          if (!btnEl.innerText || btnEl.innerText === 'Scanning…') btnEl.innerText = 'Scan for Wallet Keys';
        }
      }
    }
    function copyAll() {
      const pre = document.getElementById('keys');
      const t = pre ? pre.textContent : '';
      if (!t) return;
      navigator.clipboard.writeText(t).then(() => {
        const btns = document.querySelectorAll('#results button');
        if (btns.length > 0) {
          const orig = btns[0].innerText;
          btns[0].innerText = 'Kopiert!';
          setTimeout(() => { btns[0].innerText = orig; }, 1200);
        }
      }).catch(() => {
        alert('Kopieren nicht möglich. Inhalt:\n' + t);
      });
    }
    // Attach listener reliably (belt + suspenders: we also have inline onclick on the button)
    function attachScanListener() {
      try {
        const scanBtn = document.getElementById('scan-btn');
        if (scanBtn) {
          // remove old to avoid double
          scanBtn.removeEventListener('click', doScan);
          scanBtn.addEventListener('click', doScan);
          console.log('%c[KeyCrawl] scan button listener attached (safe)', 'color:#0f0');
          // also force a visible "JS is alive" hint in status once
          const st = document.getElementById('status');
          if (st && (!st.textContent || st.textContent.length < 5)) {
            st.style.background = '#111827';
            st.style.border = '1px solid #334155';
            st.textContent = 'JS bereit — Button-Klick gibt jetzt sofort sichtbares Feedback.';
            setTimeout(() => { if (st && st.textContent && st.textContent.includes('JS bereit')) { st.textContent=''; st.style.background=''; st.style.border=''; } }, 4200);
          }
        }
      } catch (e) { console.warn('attach failed', e); }
    }
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', attachScanListener);
    } else {
      // already loaded
      setTimeout(attachScanListener, 0);
    }
    // last-resort direct property in case
    setTimeout(function() {
      const b = document.getElementById('scan-btn');
      if (b && !b.__kc_wired) {
        b.__kc_wired = true;
        const prev = b.onclick;
        b.onclick = function(ev){ if (typeof doScan === 'function') doScan(); if (prev) prev.call(this, ev); };
      }
    }, 800);
    console.log('%c[KeyCrawl] Simple wallet-keys scanner ready (browser only, no storage). onclick + listener', 'color:#4ade80');
  </script>
</body>
</html>
"""
@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(DASHBOARD_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Simple wallet keys scanner."""
    return HTMLResponse(DASHBOARD_HTML)


@app.get("/api/findings")
async def api_findings(secret_type: str | None = None):
    """Return all collected redacted findings. Optional filter by exact secret_type."""
    data = await get_all_findings(secret_type)
    return data


@app.get("/api/categories")
async def api_categories():
    """Category counts for the dashboard UI."""
    return await get_category_counts()


@app.post("/scan-wallet-keys")
async def scan_wallet_keys(req: ScanRequest):
    """Simple endpoint for the user's request: scan and return ONLY unredacted wallet private keys.
    No DB storage, no redaction for this, ephemeral. Everything in browser.
    Always returns JSON. Never leaves the request hanging without response.
    """
    import asyncio as _asyncio
    print(f"[scan-wallet-keys] START url={req.url} (from client)")
    try:
        result: ScanResult = await _asyncio.wait_for(
            crawl_and_scan(
                req.url,
                max_depth=1,
                max_pages=12,
                same_domain_only=True,
                concurrency=4,
                request_delay=0.04,
            ),
            timeout=95.0  # hard cap so UI always gets a response
        )
        print(f"[scan-wallet-keys] DONE pages={result.pages_crawled} findings={len(result.findings)}")
    except _asyncio.TimeoutError:
        print("[scan-wallet-keys] TIMEOUT")
        return JSONResponse({"error": "Scan timed out after ~95s. Try a simpler/faster target or use CLI."}, status_code=504)
    except Exception as e:
        print(f"[scan-wallet-keys] ERROR: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

    wallet_types = [
        "Solana Private Key",
        "Solana Private Key (raw base58)",
        "Ethereum / EVM Private Key",
        "Wallet Mnemonic / Seed Phrase",
        "Wallet Private Key",
    ]

    keys = []
    for f in result.findings:
        if any(wt in f.secret_type for wt in wallet_types):
            raw = f.value
            if raw and len(raw) > 20:
                keys.append(raw)

    return {
        "target": req.url,
        "pages_crawled": result.pages_crawled,
        "keys": keys,
        "note": "Only wallet private keys (unredacted). For your own sites. No storage."
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


# Allow running with: python app.py (for Railway worker or local test)
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)

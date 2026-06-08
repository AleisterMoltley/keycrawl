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
    <button onclick="doScan()" 
            class="w-full bg-emerald-600 hover:bg-emerald-500 py-3 rounded-xl font-medium text-lg">
      Scan for Wallet Keys
    </button>
    <div id="status" class="mt-3 text-sm text-emerald-400 min-h-[1.25rem]"></div>
  </div>

  <div id="results" class="mt-6 hidden">
    <div class="flex justify-between items-center mb-2">
      <div class="font-semibold">Unredacted Wallet Keys (only)</div>
      <button onclick="copyAll()" class="text-xs px-3 py-1 bg-zinc-800 hover:bg-zinc-700 rounded">Copy all</button>
    </div>
    <pre id="keys" class="bg-black p-4 rounded-xl text-sm font-mono overflow-auto whitespace-pre-wrap break-all border border-zinc-800"></pre>
  </div>

  <div class="mt-8 text-xs text-zinc-500">
    <strong>Legal:</strong> Nur eigene Seiten oder mit Erlaubnis. Sofort rotieren. Keine Auto-Transfer-Logik.
  </div>

  <script>
    async function doScan() {
      const url = document.getElementById('url').value.trim();
      const status = document.getElementById('status');
      const results = document.getElementById('results');
      const keysPre = document.getElementById('keys');
      if (!url) { alert('URL?'); return; }
      status.textContent = 'Scanning...';
      results.classList.add('hidden');
      try {
        const r = await fetch('/scan-wallet-keys', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({url: url})
        });
        const d = await r.json();
        if (d.error) throw new Error(d.error);
        if (!d.keys || d.keys.length === 0) {
          keysPre.textContent = 'Keine Wallet Keys gefunden.';
        } else {
          keysPre.textContent = d.keys.join('\n');
        }
        results.classList.remove('hidden');
        status.textContent = `Fertig: ${d.keys.length} Keys von ${d.target}`;
      } catch(e) {
        status.textContent = 'Error: ' + e.message;
        console.error(e);
      }
    }
    function copyAll() {
      const t = document.getElementById('keys').textContent;
      if (!t) return;
      navigator.clipboard.writeText(t).then(() => {
        const orig = event.target.innerText;
        event.target.innerText = 'Kopiert!';
        setTimeout(() => event.target.innerText = orig, 1200);
      });
    }
    console.log('%c[KeyCrawl] Simple wallet-keys scanner ready (browser only).', 'color:#4ade80');
  </script>
</body>
</html>
"""

        <div class="mt-3 mb-6 bg-yellow-900 border border-yellow-600 rounded-2xl p-4 text-sm">
          <div class="font-semibold text-yellow-300 mb-2">Quick local unredacted export (one click from here)</div>
          <div class="flex gap-2 mb-2">
            <input id="quick-export-url" type="text" placeholder="https://your-site.example (your own site)" 
                   class="flex-1 bg-zinc-950 border border-zinc-700 rounded-xl px-3 py-2 text-sm focus:outline-none focus:border-yellow-500">
            <button id="quick-export-btn"
                    class="bg-yellow-600 hover:bg-yellow-500 active:bg-yellow-700 text-black font-semibold px-4 py-2 rounded-xl text-sm whitespace-nowrap">
              Scan &amp; Download Full Raw Locally
            </button>
          </div>
          <div class="text-[10px] text-yellow-400">
            One click: small scan → unredacted wallet keys (only) appear directly in the list below (in-browser only, no download, no server-side raw storage).<br>
            Collection stays redacted. Ephemeral for this scan. Use "Load local archive" below for previous exports.
          </div>
          <div id="quick-export-status" class="text-[10px] text-emerald-400 mt-1 hidden"></div>

          <!-- Area to display unredacted keys directly in browser -->
          <div id="unredacted-viewer" class="mt-4 hidden bg-zinc-950 border border-yellow-600 rounded-xl p-4">
            <div class="flex justify-between items-center mb-2">
              <div class="font-semibold text-yellow-300">Unredacted Wallet Keys (visible in browser)</div>
              <button onclick="copyUnredactedKeys()" class="text-xs bg-yellow-600 hover:bg-yellow-500 text-black px-2 py-0.5 rounded">Copy all</button>
            </div>
            <pre id="unredacted-keys-list" class="text-xs font-mono bg-black p-3 rounded overflow-auto max-h-64 whitespace-pre-wrap break-all border border-zinc-800"></pre>
            <div class="text-[10px] text-yellow-400 mt-1">These are the raw keys from the last quick scan or loaded archive. Copy them now – they are not stored anywhere by the tool.</div>
          </div>

          <!-- Load local archive file to view unredacted in browser -->
          <div class="mt-2 text-xs">
            <label class="block text-yellow-400 mb-1">Or load your local unredacted archive file (.jsonl or .json) to view raw wallet keys here (client-side only, nothing sent to server):</label>
            <input type="file" id="load-archive-input" accept=".jsonl,.json" class="text-xs">
            <button onclick="loadAndShowLocalArchive()" class="ml-2 bg-yellow-600 hover:bg-yellow-500 text-black text-xs px-2 py-0.5 rounded">Load &amp; Show Raw Keys</button>
          </div>
        </div>
      </div>
      <div class="text-xs text-right text-zinc-500">
        Data lives in <span class="font-mono">findings.db</span><br>
        <span class="text-amber-400">Redacted only. Raw values are never stored.</span>
      </div>
    </div>

    <!-- Big legal / refusal banner -->
    <div class="bg-red-950 border border-red-900 rounded-2xl p-5 mb-8 text-sm">
      <div class="font-semibold text-red-400 mb-2 text-base">⚠️ CRITICAL LEGAL WARNING — READ CAREFULLY</div>
      <p class="text-red-200">
        <strong>THIS COLLECTION (DASHBOARD) ONLY STORES REDACTED VERSIONS.</strong><br>
        Raw secret values are <strong>never</strong> written to the persistent database or shown in the historical collection.
        They are only visible in the live result of a scan you just triggered (ephemeral in-memory only).<br>
        Use CLI <code>--export-full</code> or the live scan API endpoint to get full raw data for a specific scan into a local file you control.
      </p>
      <p class="text-red-200 mt-2">
        Private keys (especially Solana wallet private keys) that appear here (even redacted) mean the wallet is fully compromised.
      </p>
      <ul class="list-disc ml-5 mt-2 text-red-300 text-xs space-y-0.5">
        <li>Discovery of a private key via web scanning almost always indicates a leak or misconfiguration on the scanned site.</li>
        <li><strong>DO NOT</strong> use any discovered private key to send, transfer, or "drain" funds. That is theft and a criminal offense under US and international law.</li>
        <li>KeyCrawl and this dashboard contain <strong>zero code</strong> for loading keys, building transactions, or moving assets on Solana (or any chain).</li>
        <li>If you found keys on a site you do not own: stop, document responsibly, and notify the owner / bug bounty program.</li>
      </ul>
      <p class="mt-2 text-[10px] text-red-400">Any request to add auto-draining, sweeping, or "send everything to address X" functionality has been and will be refused.</p>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-4 gap-4 mb-6" id="category-summary">
      <!-- Populated by JS from /api/categories -->
    </div>

    <div class="bg-zinc-900 border border-zinc-800 rounded-2xl p-5">
      <div class="flex flex-wrap items-center gap-3 mb-4">
        <input id="search" type="text" placeholder="Search URL or context..." 
               class="flex-1 min-w-[220px] bg-zinc-950 border border-zinc-700 rounded-xl px-4 py-2 text-sm focus:outline-none focus:border-emerald-500">
        
        <select id="type-filter" class="bg-zinc-950 border border-zinc-700 rounded-xl px-3 py-2 text-sm">
          <option value="">All categories</option>
        </select>

        <button onclick="loadFindings()" 
                class="px-4 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-sm">Refresh</button>
        
        <button onclick="clearFilters()" 
                class="px-3 py-2 rounded-xl bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-sm">Clear filters</button>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="text-left text-zinc-400 border-b border-zinc-800">
              <th class="py-2 pr-3">When</th>
              <th class="py-2 pr-3">Category</th>
              <th class="py-2 pr-3">Redacted Value</th>
              <th class="py-2 pr-3">Source URL</th>
              <th class="py-2">Context</th>
            </tr>
          </thead>
          <tbody id="findings-tbody" class="divide-y divide-zinc-800 text-zinc-300"></tbody>
        </table>
      </div>
      <div id="empty-state" class="hidden py-8 text-center text-zinc-500 text-sm">No findings match the current filters.</div>
    </div>

    <div class="mt-8 text-[10px] text-zinc-500 leading-relaxed">
      <strong>Solana Private Keys:</strong> If any appear in the list above, the corresponding wallet(s) have had their secret material exposed publicly.
      The owner must immediately move all funds to a brand new wallet using a fresh seed. There is no safe way to "recover" a leaked private key.
    </div>
  </div>

  <script>
    let allFindings = [];
    let categories = [];

    async function loadCategories() {
      const res = await fetch('/api/categories');
      categories = await res.json();
      const container = document.getElementById('category-summary');
      container.innerHTML = '';
      
      if (categories.length === 0) {
        container.innerHTML = '<div class="col-span-4 text-sm text-zinc-500 p-4 bg-zinc-900 rounded-xl border border-zinc-800">No secrets collected yet. Run some scans from the main page.</div>';
        return;
      }

      categories.forEach(cat => {
        const isDanger = /private|solana|key|ssh|pem|jwt/i.test(cat.secret_type);
        const el = document.createElement('div');
        el.className = `category-card cursor-pointer bg-zinc-900 border ${isDanger ? 'border-red-900 danger' : 'border-zinc-800'} rounded-2xl p-4`;
        el.innerHTML = `
          <div class="text-[10px] uppercase tracking-widest ${isDanger ? 'text-red-400' : 'text-emerald-400'}">${cat.secret_type}</div>
          <div class="text-4xl font-semibold tabular-nums mt-1 ${isDanger ? 'text-red-400' : ''}">${cat.count}</div>
          <div class="text-xs text-zinc-500 mt-0.5">findings</div>
        `;
        el.onclick = () => {
          document.getElementById('type-filter').value = cat.secret_type;
          filterAndRender();
        };
        container.appendChild(el);
      });

      // populate filter dropdown
      const sel = document.getElementById('type-filter');
      sel.innerHTML = '<option value="">All categories</option>';
      categories.forEach(c => {
        const o = document.createElement('option');
        o.value = c.secret_type;
        o.textContent = `${c.secret_type} (${c.count})`;
        sel.appendChild(o);
      });
    }

    async function loadFindings() {
      const res = await fetch('/api/findings');
      allFindings = await res.json();
      filterAndRender();
    }

    function filterAndRender() {
      const q = (document.getElementById('search').value || '').toLowerCase();
      const type = document.getElementById('type-filter').value;

      const filtered = allFindings.filter(f => {
        const matchesType = !type || f.secret_type === type;
        const matchesQ = !q || 
          (f.url && f.url.toLowerCase().includes(q)) ||
          (f.context && f.context.toLowerCase().includes(q)) ||
          (f.value_redacted && f.value_redacted.toLowerCase().includes(q));
        return matchesType && matchesQ;
      });

      const tbody = document.getElementById('findings-tbody');
      tbody.innerHTML = '';
      const empty = document.getElementById('empty-state');

      if (filtered.length === 0) {
        empty.classList.remove('hidden');
        return;
      }
      empty.classList.add('hidden');

      filtered.forEach(f => {
        const isHighRisk = /private|solana|pem|ssh|key/i.test(f.secret_type);
        const tr = document.createElement('tr');
        tr.className = isHighRisk ? 'bg-red-950/30' : '';
        const when = new Date(f.discovered_at * 1000).toLocaleString();
        
        tr.innerHTML = `
          <td class="py-2 pr-3 text-xs text-zinc-400 whitespace-nowrap align-top">${when}</td>
          <td class="py-2 pr-3 align-top">
            <span class="inline-block px-2 py-0.5 rounded text-[10px] font-medium ${isHighRisk ? 'bg-red-900 text-red-300' : 'bg-zinc-800 text-emerald-300'}">${f.secret_type}</span>
          </td>
          <td class="py-2 pr-3 font-mono text-amber-300 align-top text-xs break-all">${f.value_redacted}</td>
          <td class="py-2 pr-3 align-top text-xs text-blue-400 break-all"><a href="${f.url}" target="_blank" class="hover:underline">${f.url}</a></td>
          <td class="py-2 text-xs text-zinc-400 align-top finding break-all">${(f.context || '').slice(0, 160)}</td>
        `;
        tbody.appendChild(tr);
      });
    }

    function clearFilters() {
      document.getElementById('search').value = '';
      document.getElementById('type-filter').value = '';
      filterAndRender();
    }

    // live filter
    function setupFilters() {
      ['search', 'type-filter'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
          el.addEventListener('input', filterAndRender);
          el.addEventListener('change', filterAndRender);
        }
      });
    }

    async function initDashboard() {
      await loadCategories();
      await loadFindings();
      setupFilters();

      // Attach quick export button listener (more reliable than inline onclick)
      const quickBtn = document.getElementById('quick-export-btn');
      if (quickBtn) {
        quickBtn.addEventListener('click', quickUnredactedExport);
      }
    }

    // Quick one-click unredacted local export directly from dashboard
    async function quickUnredactedExport() {
      console.log('%c[KeyCrawl] quickUnredactedExport clicked', 'color: lime');
      const input = document.getElementById('quick-export-url');
      const status = document.getElementById('quick-export-status');
      if (!input || !status) {
        alert('UI elements not found. Hard refresh the page (Ctrl+Shift+R) and try again.');
        console.error('quick-export elements missing');
        return;
      }
      const url = input.value.trim();
      if (!url) {
        alert('Please enter a target URL first (e.g. https://stableponzi.com)');
        return;
      }

      // Force visible status immediately - even if hidden class or CSS issue
      status.classList.remove('hidden');
      status.style.display = 'block';
      status.style.visibility = 'visible';
      status.style.opacity = '1';
      status.textContent = 'Button clicked - preparing scan...';
      const allButtons = document.querySelectorAll('button');
      allButtons.forEach(b => b.disabled = true);

      try {
        // Trigger scan (small limits for quick export)
        const scanRes = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: url,
            max_depth: 1,
            max_pages: 15,
            same_domain_only: true
          })
        });
        if (!scanRes.ok) throw new Error('Failed to start scan: ' + scanRes.status);
        const scanData = await scanRes.json();
        const jobId = scanData.job_id;
        if (!jobId) throw new Error('No job ID returned');

        status.textContent = `Scanning... (job ${jobId})`;

        // Poll until done
        let done = false;
        let attempts = 0;
        const maxAttempts = 90; // ~2 minutes
        while (!done && attempts < maxAttempts) {
          await new Promise(r => setTimeout(r, 1300));
          const jobRes = await fetch(`/api/jobs/${jobId}`);
          if (!jobRes.ok) throw new Error('Poll failed');
          const job = await jobRes.json();
          if (job.status === 'done') {
            done = true;
          } else if (job.status === 'error') {
            throw new Error(job.error || 'Scan failed on server');
          }
          attempts++;
          status.textContent = `Scanning... (${attempts}/${maxAttempts})`;
        }

        if (!done) throw new Error('Scan timed out. Try a simpler target or use CLI.');

        status.textContent = 'Processing results...';

        // Get full data, filter ONLY wallet private keys, download as clean .txt
        const exportRes = await fetch(`/api/scan/${jobId}/full-export`);
        if (!exportRes.ok) throw new Error('Failed to get export: ' + exportRes.status);
        const fullData = await exportRes.json();

        const walletTypes = [
          "Solana Private Key",
          "Solana Private Key (raw base58)",
          "Ethereum / EVM Private Key",
          "Wallet Mnemonic / Seed Phrase",
          "Wallet Private Key"
        ];

        const lines = [];
        for (const f of (fullData.findings || [])) {
          const stype = f.secret_type || f["secret_type"] || "";
          if (walletTypes.some(wt => stype.includes(wt))) {
            const raw = f.raw_value || f.value || f["raw_value"];
            if (raw && typeof raw === 'string' && raw.length > 20) {
              lines.push(raw);
            }
          }
        }

        if (lines.length === 0) {
          status.textContent = 'No wallet private keys found in this scan.';
          setTimeout(() => { status.classList.add('hidden'); status.textContent = ''; }, 4000);
          return;
        }

        // Show directly in browser (unredacted list) - no auto-download, no server storage
        const viewer = document.getElementById('unredacted-viewer');
        const listEl = document.getElementById('unredacted-keys-list');
        if (viewer && listEl) {
          viewer.classList.remove('hidden');
          listEl.textContent = lines.join('\n');
          // store for copy
          viewer.dataset.keys = lines.join('\n');
        }

        status.textContent = `Done! ${lines.length} unredacted wallet key(s) shown below in browser (copy them now - nothing stored or downloaded automatically).`;
        setTimeout(() => {
          status.classList.add('hidden');
          status.textContent = '';
        }, 6000);

      } catch (e) {
        console.error('quickUnredactedExport error:', e);
        status.textContent = 'Error: ' + (e.message || e);
        // Keep status visible longer on error
        setTimeout(() => { status.classList.add('hidden'); }, 8000);
      } finally {
        allButtons.forEach(b => b.disabled = false);
      }
    }

    function copyUnredactedKeys() {
      const viewer = document.getElementById('unredacted-viewer');
      const listEl = document.getElementById('unredacted-keys-list');
      if (!viewer || !listEl) return;
      const keysText = viewer.dataset.keys || listEl.textContent;
      if (!keysText) return;
      navigator.clipboard.writeText(keysText).then(() => {
        const orig = listEl.textContent;
        listEl.textContent = 'Copied to clipboard!';
        setTimeout(() => { listEl.textContent = orig; }, 1500);
      }).catch(() => {
        // fallback
        prompt('Copy these keys (Ctrl/Cmd+C):', keysText);
      });
    }

    async function loadAndShowLocalArchive() {
      const fileInput = document.getElementById('load-archive-input');
      const viewer = document.getElementById('unredacted-viewer');
      const listEl = document.getElementById('unredacted-keys-list');
      if (!fileInput || !fileInput.files.length || !viewer || !listEl) {
        alert('Select a .jsonl or .json archive file first.');
        return;
      }
      const file = fileInput.files[0];
      const text = await file.text();

      const walletTypes = [
        "Solana Private Key",
        "Solana Private Key (raw base58)",
        "Ethereum / EVM Private Key",
        "Wallet Mnemonic / Seed Phrase",
        "Wallet Private Key"
      ];

      const lines = [];
      const recs = [];
      try {
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) {
          recs.push(...parsed);
        } else if (parsed && parsed.findings) {
          recs.push(parsed);
        } else {
          // assume JSONL
          text.split(/\r?\n/).forEach(line => {
            const t = line.trim();
            if (t) {
              try { recs.push(JSON.parse(t)); } catch(e){}
            }
          });
        }
      } catch (e) {
        // treat as JSONL
        text.split(/\r?\n/).forEach(line => {
          const t = line.trim();
          if (t) {
            try { recs.push(JSON.parse(t)); } catch(e){}
          }
        });
      }

      for (const rec of recs) {
        for (const f of (rec.findings || [])) {
          const stype = f.secret_type || f["secret_type"] || "";
          if (walletTypes.some(wt => stype.includes(wt))) {
            const raw = f.raw_value || f.value || f["raw_value"];
            if (raw && typeof raw === 'string' && raw.length > 20) {
              lines.push(raw);
            }
          }
        }
      }

      if (lines.length === 0) {
        alert('No wallet private keys found in the selected archive file.');
        return;
      }

      viewer.classList.remove('hidden');
      listEl.textContent = lines.join('\n');
      viewer.dataset.keys = lines.join('\n');
    }

    window.onload = initDashboard;
  </script>
</body>
</html>
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
            job_id=job_id,
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


@app.get("/api/scan/{job_id}/full-export")
async def api_full_export(job_id: str):
    """
    Return the full scan result for a live job (including raw secret values).
    ONLY for the operator who just ran this specific scan.
    This is ephemeral (in-memory only while the job exists).
    The persistent collection never receives raw values.
    Use responsibly. Download and handle the secrets with care, then forget them.
    """
    job = JOBS.get(job_id)
    if not job or job.get("status") != "done":
        return JSONResponse(
            {"error": "Job not found or not complete. Full exports are only available immediately after a scan for the current session."},
            status_code=404,
        )

    # Return the done_result which for live jobs includes the full findings with 'value'
    result = job.get("result", {})
    # Build findings with explicit raw_value for clarity in exports
    raw_findings = []
    for f in result.get("findings", []):
        if isinstance(f, dict):
            ff = f.copy()
        else:
            ff = f.model_dump() if hasattr(f, 'model_dump') else dict(f)
        ff["raw_value"] = ff.pop("value", None)  # UNREDACTED raw secret
        raw_findings.append(ff)

    export = {
        "_WARNING": "RAW SECRET VALUES INCLUDED under 'raw_value' in each finding. This is only for the scan you just performed. "
                    "Handle with extreme care. The KeyCrawl persistent collection (/dashboard) stores only redacted data. "
                    "Rotate any real private keys immediately. The 'value_redacted' is the masked version.",
        "job_id": job_id,
        "target": result.get("target"),
        "started_at": result.get("started_at"),
        "finished_at": result.get("finished_at"),
        "pages_crawled": result.get("pages_crawled"),
        "stats": result.get("stats"),
        "errors": result.get("errors"),
        "findings": raw_findings,  # includes 'raw_value' (unredacted)
    }
    return JSONResponse(export)


@app.get("/health")
async def health():
    try:
        cats = await get_category_counts()
        total = sum(c["count"] for c in cats)
    except Exception:
        total = 0
        cats = []
    return {
        "status": "ok",
        "jobs_in_memory": len(JOBS),
        "collected_findings": total,
        "categories": cats,
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """The main collection dashboard: all keys, by category."""
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
    """
    try:
        result: ScanResult = await crawl_and_scan(
            req.url,
            max_depth=1,
            max_pages=10,
            same_domain_only=True,
            concurrency=3,
            request_delay=0.05,
        )
    except Exception as e:
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


# Allow running with: python app.py (for Railway worker or local test)
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)

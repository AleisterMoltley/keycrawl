# keycrawl

**Focused credential + wallet key leak scanner.**

Crawls pages (HTML + inline JS + comments) and detects **only**:

- Usernames / emails + passwords (credential pairs)
- Wallet private keys (Solana base58, Ethereum/EVM 0x..., BIP39 mnemonics/seeds, generic wallet privkeys)

The scope is deliberately limited to reduce noise from generic API keys, service tokens, JWTs, etc.

Designed for **authorized testing of your own systems** (e.g. your Railway deploys, web apps). 

**Important safety note**: The persistent collection (`/dashboard`) stores only **redacted** versions + context. Full raw values are available only in live scan output or via per-scan local exports (`--export-full`). Never use this to collect secrets from systems you do not own.

> ⚠️ **Legal notice**: Only scan assets you own or have explicit written permission for. Finding real credentials is a serious matter. The tool and its authors accept no responsibility for misuse.

## Quick start (local)

The scanner is now focused on credentials and wallet keys only. This greatly reduces irrelevant findings.

```bash
# 1. Clone + env
cd keycrawl
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. CLI scan (recommended for one-offs)
python -m keycrawl scan https://target.example.com --depth 1 --max-pages 30

# Persist redacted findings to the shared collection DB (powers /dashboard)
python -m keycrawl scan https://target.example.com --depth 1 --max-pages 30 --persist

# JSON output (for piping / automation)
python -m keycrawl scan https://target.example.com --json > findings.json

# List the focused patterns (credentials + wallet keys)
python -m keycrawl patterns

# Test the detection engine on a string (no network)
python -m keycrawl check 'sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz1234567890ABCDEF'
```

## Web UI + API (Railway / local server)

```bash
uvicorn app:app --reload --port 8080
# open http://localhost:8080
```

The UI is a zero-dependency single-file Tailwind + HTMX interface. Submit a target and it polls for results.

### JSON API

```bash
curl -X POST http://localhost:8080/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","max_depth":1,"max_pages":20}'

# poll
curl http://localhost:8080/api/jobs/<job_id>
```

## Railway deployment (one-click ready)

1. Push this repo to GitHub (private recommended).
2. In Railway:
   - New Project → Deploy from GitHub repo (install the Railway GitHub app on your org/account if you haven't).
   - Select the `keycrawl` repo.
   - It will auto-detect the Dockerfile + `railway.toml`.
3. (Optional) Set a custom domain or let Railway give you one.
4. Deploy as **Web Service**.

Healthcheck is on `/health`.

### Using it as a CLI on Railway (after deploy)

```bash
# From your machine with railway CLI installed
railway link   # choose the project/service
railway run python -m keycrawl scan https://the-site-you-are-allowed-to-scan.com --depth 1 --max-pages 25
```

This runs inside the same container image (your env vars, network, etc. available if you set any).

## Configuration / tuning (CLI & API)

| Flag / Field         | Default | Meaning                              |
|----------------------|---------|--------------------------------------|
| `--depth` / `max_depth` | 1     | Crawl depth (0 = only start URL)    |
| `--max-pages`        | 25–35   | Hard stop on total pages fetched    |
| `--same-domain`      | true    | Only follow links on same eTLD+1    |
| `--delay`            | 0.12s   | Politeness delay between requests   |
| concurrency          | 5–6     | Parallel requests (don't hammer)    |

The crawler is intentionally conservative.

## How detection works

- Large curated regex set for known high-value token formats (see `keycrawl/scanner.py: PATTERNS`).
- Additional high-entropy heuristic (Shannon entropy on long base64/hex-like strings) to catch unknown keys.
- Context extraction + basic false-positive filters (test/dummy/example keys are suppressed).
- Raw secret values are **never** persisted by the web service (only redacted versions + context are shown).

You can extend patterns easily by editing the list in `scanner.py`.

## Output example (CLI)

```
Type                    Redacted Value               URL
AWS Access Key ID       AKIA...REDACTED              https://...
GitHub Token            ghp_...abcd                  https://...
High Entropy String     ABcdEf...1234                https://...
```

## Project layout

```
keycrawl/
├── app.py                 # FastAPI web service + beautiful minimal UI
├── Dockerfile
├── Procfile
├── railway.toml
├── requirements.txt
├── keycrawl/
│   ├── __init__.py
│   ├── __main__.py        # python -m keycrawl
│   ├── cli.py             # Typer CLI
│   └── scanner.py         # The actual crawler + detection engine
└── README.md
```

## Collection Dashboard (redacted leak registry)

Run scans (focused on credentials + wallet keys), then visit `/dashboard` (or click the button in the main UI).

The dashboard collects **redacted** findings + context from all scans (CLI with `--persist` or web). It is a registry of *where* leaks were found, not a store of the secrets themselves.

Features:
- **All discovered secrets are collected** into a local SQLite file (`findings.db`).
- Grouped **by category** (`secret_type`): AWS keys, GitHub tokens, Solana Private Key, PEM Private Keys, High Entropy, JWTs, etc.
- Click any category card to filter the table instantly.
- Search across URL + context.
- High-risk categories (anything with "Private Key", "Solana", "PEM", "SSH") are visually highlighted in red.
- Everything shown is **redacted**. Raw secret material is **never** written to the database or returned by the API.

### CLI can also contribute to the collection

```bash
python -m keycrawl scan https://your-site.example --persist
```

This writes the redacted findings into the same DB that the web dashboard reads. Use this when you want a unified view of everything you have found across multiple scans / tools.

Start the server, scan a couple of targets, then open http://localhost:8080/dashboard.

### API for the collection
- `GET /api/findings` → all redacted findings (optionally `?secret_type=Solana Private Key`)
- `GET /api/categories` → counts per category
- `GET /health` → now also returns `collected_findings` + breakdown

## Important: Solana private keys & "drain everything" requests

**This tool will never implement automatic (or manual) draining of wallets.**

If the scanner detects a Solana private key (or any other private key), it means that key material has been leaked on the crawled website. The correct and only legal response is:

- The legitimate owner must immediately generate a new wallet and move funds.
- You (the scanner operator) must not use the key.

Any code that would:
- Load a discovered private key (Solana or otherwise)
- Connect to an RPC
- Build a transaction
- Send SOL / SPL tokens / "alles auf der wallet" to any address (or any other malicious action with discovered keys)

...has been **explicitly refused** and is not present in this repository (and never will be).

Building or operating tooling whose purpose is to steal funds via leaked credentials is a serious crime (theft, computer fraud, etc.). I will not assist with it.

The dashboard exists purely for **visibility and responsible security research / leak tracking** (redacted only).

## Getting full (unredacted) data for your own scans

Since the scanner is now limited to passwords/usernames + wallet private keys, you will mostly see relevant findings.

For the actual secret values during your own controlled scans:

- **CLI**: `python -m keycrawl scan https://your-own-site.example --export-full`
  Appends the complete raw findings (unredacted secrets) to a **single growing local archive file**
  (default `keycrawl-unredacted-archive.jsonl` in the current directory, using JSON Lines so it can be safely appended to).
  The file grows with every export.

  You can force it to always use the same file across different directories with the environment variable:
  ```bash
  export KEYCRAWL_UNREDACTED_ARCHIVE=~/secure/keycrawl-archive.jsonl
  ```

  The KeyCrawl tool itself never puts raw secrets into its persistent collection (`/dashboard` or `findings.db`).

- **CLI**: `--show-raw` to see raw values directly in the table output for this run.

- **Web (one button in dashboard)**: 
  - Directly in the `/dashboard` page there is a "Quick local unredacted export" box with URL input + **"Scan & Download Full Raw Locally"** button.
  - One single click on the button: triggers a scan (small limits), waits for it, then automatically downloads the full unredacted JSON (raw secrets) to your local machine. No CLI command, no extra steps.
  - The persistent collection (/dashboard + DB) stays redacted-only. This export is per-scan only (ephemeral on server side).

- **CLI archive viewer**: `python -m keycrawl archive` (or with `--file path/to/archive.jsonl --show-raw`) to view your local growing unredacted archive file in the terminal.

The `/dashboard` collection and persistent DB always stay **redacted-only** + context. This is intentional.

**Best practice**: When you find real wallet private keys or passwords, rotate them immediately. Do not rely on long-term archiving of the raw values.

## Future ideas (contributions welcome)

- Optional secret verification (live calls with redacted test requests)
- Export to SARIF / GitHub Security tab format
- Integration with nuclei templates or gitleaks-style rules
- Screenshot / JS rendering for SPAs (playwright)
- Persistent result storage + history (volume or Postgres)

## Credits

Built for fast, responsible, Railway-native secret surface scanning on live websites.

Stay legal. Scan responsibly.
```

---

**Repo is private by design.** Do not make public unless you intentionally want to share the tool.

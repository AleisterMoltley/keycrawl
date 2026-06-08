# keycrawl

**Website secrets scanner.** Crawls pages (HTML + inline JS + comments) and detects:

- API keys & tokens (AWS, Google, GitHub, Slack, Stripe, Twilio, SendGrid, Heroku, …)
- Private keys (RSA, OpenSSH, EC, PGP, etc.)
- JWTs
- High-entropy strings (unknown but suspicious secrets)
- Generic `api_key = "..."` style assignments

Designed for **authorized security testing**, bug bounties, and red team / defensive work.

> ⚠️ **Legal notice**: Only scan assets you own or have explicit written permission for. Finding real credentials is a serious matter. The tool and its authors accept no responsibility for misuse.

## Quick start (local)

```bash
# 1. Clone + env
cd keycrawl
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. CLI scan (recommended for one-offs)
python -m keycrawl scan https://target.example.com --depth 1 --max-pages 30

# JSON output (for piping / automation)
python -m keycrawl scan https://target.example.com --json > findings.json

# List patterns
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

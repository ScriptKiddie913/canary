"""
TRIPWIRE — per‑visitor AWS canary honeypot
--------------------------------------------------------------------
Single‑file FastAPI service. Serves fake credential files (.env,
kubeconfig, cloud‑keys.json). Every distinct visitor who pulls a trap
file gets their own live‑looking AWS key, minted on the fly via
canarytokens.org's free public API (no signup, no AWS account, no
API key required on our side). If that key is ever used against AWS
from anywhere, canarytokens.org posts a webhook back here, and this
service correlates the trigger to the original harvest event and
fires a Telegram alert naming both ends.

Persistence: SQLite on a Render persistent disk (single instance only —
do not scale this service horizontally without moving to Postgres,
since SQLite on a disk is not shared across instances).

Enhanced:
 - Robust minting with retries and fallback logging.
 - Automatic keep‑alive ping to prevent Render from sleeping.
 - Top‑notch crypto vault landing page.
 - Lifespan events (no deprecation warnings).
 - Test‑mint returns raw response for easy debugging.
"""
import os
import json
import time
import hashlib
import secrets
import base64
import logging
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional, Dict, Any

import httpx
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tripwire")

# ---------------------------------------------------------------------------
# Configuration (all via environment variables – no secrets in code)
# ---------------------------------------------------------------------------
DB_PATH_ENV = os.environ.get("DB_PATH", "")
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "")
MINT_DEDUPE_HOURS = float(os.environ.get("MINT_DEDUPE_HOURS", "24"))

CANARYTOKENS_GENERATE_URL = "https://canarytokens.org/generate"
IP_GEO_URL = "http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,hosting,proxy"

FALLBACK_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
FALLBACK_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

import sqlite3

# ---------------------------------------------------------------------------
# Determine a writable database path
# ---------------------------------------------------------------------------
def resolve_db_path() -> str:
    if DB_PATH_ENV:
        candidate = DB_PATH_ENV
        try:
            dirname = os.path.dirname(candidate)
            if dirname:
                os.makedirs(dirname, exist_ok=True)
                test_file = os.path.join(dirname, ".write_test")
                with open(test_file, "w") as f:
                    f.write("ok")
                os.remove(test_file)
                log.info("Using database path: %s", candidate)
                return candidate
        except Exception as e:
            log.warning("DB_PATH '%s' is not writable: %s. Falling back to local path.", candidate, e)

    fallback = os.path.join(os.getcwd(), "data", "tripwire.db")
    os.makedirs(os.path.dirname(fallback), exist_ok=True)
    log.info("Using fallback database path: %s", fallback)
    return fallback

DB_PATH = resolve_db_path()

# ---------------------------------------------------------------------------
# Database utilities
# ---------------------------------------------------------------------------
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS harvests (
            id TEXT PRIMARY KEY,
            trap_type TEXT NOT NULL,
            visitor_ip TEXT NOT NULL,
            user_agent TEXT,
            headers_json TEXT,
            harvested_at REAL NOT NULL,
            canary_token_code TEXT,
            access_key_id TEXT,
            secret_access_key TEXT,
            memo TEXT,
            triggered INTEGER DEFAULT 0,
            harvest_geo TEXT
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS triggers (
            id TEXT PRIMARY KEY,
            harvest_id TEXT,
            canary_token_code TEXT,
            trigger_ip TEXT,
            trigger_time REAL NOT NULL,
            raw_payload TEXT,
            trigger_geo TEXT
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_h_ip_trap ON harvests(visitor_ip, trap_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_h_token ON harvests(canary_token_code)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_t_harvest ON triggers(harvest_id)")

init_db()

# ---------------------------------------------------------------------------
# FastAPI app with lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    asyncio.create_task(keep_alive())
    yield
    # Shutdown (nothing to clean up)

app = FastAPI(title="Tripwire Console", docs_url=None, redoc_url=None, lifespan=lifespan)
security = HTTPBasic()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def fake_password(seed: str, length: int = 18) -> str:
    return hashlib.sha256((seed + "tripwire-decoy-salt").encode()).hexdigest()[:length]

async def geo_lookup(ip: str) -> str:
    if not ip or ip == "unknown":
        return "unknown"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(IP_GEO_URL.format(ip=ip))
            d = r.json()
            if d.get("status") == "success":
                tag = " [DATACENTER/HOSTING]" if d.get("hosting") else ""
                proxy_tag = " [PROXY]" if d.get("proxy") else ""
                return f"{d.get('as', '?')} | {d.get('org', '?')} | {d.get('country', '?')}{tag}{proxy_tag}"
    except Exception as e:
        log.warning("geo_lookup failed for %s: %s", ip, e)
    return "unknown"

async def notify_telegram(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.info("Telegram not configured, skipping alert: %s", text[:120])
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, data={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            })
            if resp.status_code != 200:
                log.warning("Telegram send failed: %s %s", resp.status_code, resp.text[:300])
    except Exception as e:
        log.warning("Telegram send exception: %s", e)

async def mint_canary(harvest_id: str, trap_type: str, retries: int = 3) -> Optional[Dict[str, Any]]:
    """
    Mint a fresh AWS Keys Canarytoken via canarytokens.org's free public API.
    Implements retries with exponential backoff.
    """
    memo = f"tripwire:{trap_type}:{harvest_id[:8]}"
    payload = {"type": "aws_keys", "memo": memo}
    if BASE_URL:
        payload["webhook_url"] = f"{BASE_URL}/webhook/canarytoken"

    for attempt in range(1, retries + 1):
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(CANARYTOKENS_GENERATE_URL, data=payload)
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            log.error("mint_canary attempt %d/%d failed: %s", attempt, retries, e)
            if attempt < retries:
                await asyncio.sleep(2 ** attempt)  # exponential backoff
                continue
            return None

        access_key_id = data.get("access_key_id")
        secret_access_key = data.get("secret_access_key")
        token_code = data.get("canarytoken") or data.get("token")

        if not access_key_id or not secret_access_key:
            log.error("mint_canary unexpected response shape, raw=%s", json.dumps(data)[:1000])
            if attempt < retries:
                await asyncio.sleep(2 ** attempt)
                continue
            return None

        return {
            "token_code": token_code,
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "memo": memo,
        }

    return None

async def handle_trap(request: Request, trap_type: str) -> Dict[str, Any]:
    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "")
    now = time.time()

    with db() as conn:
        cutoff = now - MINT_DEDUPE_HOURS * 3600
        existing = conn.execute(
            """SELECT * FROM harvests
               WHERE visitor_ip=? AND trap_type=? AND triggered=0 AND harvested_at>?
               ORDER BY harvested_at DESC LIMIT 1""",
            (ip, trap_type, cutoff),
        ).fetchone()

    if existing:
        return {
            "harvest_id": existing["id"],
            "access_key_id": existing["access_key_id"],
            "secret_access_key": existing["secret_access_key"],
        }

    harvest_id = secrets.token_hex(8)
    minted = await mint_canary(harvest_id, trap_type)
    fallback_used = False
    if not minted:
        fallback_used = True
        minted = {
            "token_code": None,
            "access_key_id": FALLBACK_ACCESS_KEY,
            "secret_access_key": FALLBACK_SECRET_KEY,
            "memo": f"tripwire:{trap_type}:{harvest_id[:8]}:MINT_FAILED",
        }

    geo = await geo_lookup(ip)

    with db() as conn:
        conn.execute(
            """INSERT INTO harvests
               (id, trap_type, visitor_ip, user_agent, headers_json, harvested_at,
                canary_token_code, access_key_id, secret_access_key, memo, triggered, harvest_geo)
               VALUES (?,?,?,?,?,?,?,?,?,?,0,?)""",
            (harvest_id, trap_type, ip, ua, json.dumps(dict(request.headers)), now,
             minted.get("token_code"), minted["access_key_id"], minted["secret_access_key"],
             minted["memo"], geo),
        )

    warn = " ⚠️ MINT FAILED — fallback AWS example key served, not monitored" if fallback_used else ""
    await notify_telegram(
        "🪤 <b>TRAP SPRUNG</b>\n"
        f"Type: {trap_type}\n"
        f"IP: {ip}\n"
        f"Geo: {geo}\n"
        f"UA: {ua[:150]}\n"
        f"Harvest ID: {harvest_id}{warn}"
    )

    return {
        "harvest_id": harvest_id,
        "access_key_id": minted["access_key_id"],
        "secret_access_key": minted["secret_access_key"],
    }

def check_auth(credentials: HTTPBasicCredentials = Depends(security)) -> bool:
    if not DASHBOARD_PASS:
        raise HTTPException(status_code=503, detail="DASHBOARD_PASS not configured")
    user_ok = secrets.compare_digest(credentials.username, DASHBOARD_USER)
    pass_ok = secrets.compare_digest(credentials.password, DASHBOARD_PASS)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return True

# ---------------------------------------------------------------------------
# Trap endpoints
# ---------------------------------------------------------------------------
@app.get("/.env", response_class=PlainTextResponse)
async def trap_env(request: Request):
    d = await handle_trap(request, "env_file")
    content = f"""# Application Environment Configuration
APP_ENV=production
APP_DEBUG=false
APP_NAME=core-api
APP_URL=https://api.internal.example.com

DB_CONNECTION=pgsql
DB_HOST=10.0.4.12
DB_PORT=5432
DB_DATABASE=prod_core
DB_USERNAME=svc_app
DB_PASSWORD={fake_password(d['harvest_id'])}

REDIS_HOST=10.0.4.20
REDIS_PORT=6379
REDIS_PASSWORD={fake_password(d['harvest_id'] + 'redis', 14)}

JWT_SECRET={hashlib.sha256(d['harvest_id'].encode()).hexdigest()}

AWS_ACCESS_KEY_ID={d['access_key_id']}
AWS_SECRET_ACCESS_KEY={d['secret_access_key']}
AWS_DEFAULT_REGION=us-east-1
AWS_S3_BUCKET=core-prod-backups

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_USERNAME=postmaster@internal.example.com
MAIL_PASSWORD={fake_password(d['harvest_id'] + 'mail', 14)}
"""
    return PlainTextResponse(content)

@app.get("/kubeconfig.yaml", response_class=PlainTextResponse)
@app.get("/.kube/config", response_class=PlainTextResponse)
async def trap_kubeconfig(request: Request):
    d = await handle_trap(request, "kubeconfig")
    ca_data = base64.b64encode(hashlib.sha256(d["harvest_id"].encode()).digest()).decode()
    content = f"""apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://B7E2A9F1C4D8E6A3B2C1D0E9F8A7B6C5.gr7.us-east-1.eks.amazonaws.com
    certificate-authority-data: {ca_data}
  name: prod-cluster.us-east-1.eksctl.io
contexts:
- context:
    cluster: prod-cluster.us-east-1.eksctl.io
    user: prod-cluster.us-east-1.eksctl.io
    namespace: default
  name: prod-cluster.us-east-1.eksctl.io
current-context: prod-cluster.us-east-1.eksctl.io
preferences: {{}}
users:
- name: prod-cluster.us-east-1.eksctl.io
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws-iam-authenticator
      args:
        - token
        - -i
        - prod-cluster
      env:
        - name: AWS_ACCESS_KEY_ID
          value: {d['access_key_id']}
        - name: AWS_SECRET_ACCESS_KEY
          value: {d['secret_access_key']}
        - name: AWS_DEFAULT_REGION
          value: us-east-1
"""
    return PlainTextResponse(content)

@app.get("/backup/cloud-keys.json")
async def trap_cloud_keys(request: Request):
    d = await handle_trap(request, "cloud_keys")
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "aws": {
            "access_key_id": d["access_key_id"],
            "secret_access_key": d["secret_access_key"],
            "region": "us-east-1",
        },
        "backup_bucket": "core-prod-backups",
        "rotation_policy_days": 90,
        "notes": "rotate before Q-end audit",
    }
    return JSONResponse(payload)

@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    return PlainTextResponse(
        "User-agent: *\n"
        "Disallow: /backup/\n"
        "Disallow: /.env\n"
        "Disallow: /.kube/\n"
        "Disallow: /kubeconfig.yaml\n"
    )

# ---------------------------------------------------------------------------
# Webhook receiver – canarytokens.org calls this when a minted key is used
# ---------------------------------------------------------------------------
@app.post("/webhook/canarytoken")
async def canary_webhook(request: Request):
    try:
        payload = await request.json()
    except Exception:
        form = await request.form()
        payload = dict(form)

    token_code = payload.get("canarytoken") or payload.get("Token") or payload.get("token")
    trigger_ip = (
        payload.get("src_ip")
        or payload.get("SourceIP")
        or payload.get("source_ip")
        or "unknown"
    )
    now = time.time()
    trigger_id = secrets.token_hex(8)

    with db() as conn:
        harvest_row = None
        if token_code:
            harvest_row = conn.execute(
                "SELECT * FROM harvests WHERE canary_token_code=?", (token_code,)
            ).fetchone()

        geo = await geo_lookup(trigger_ip) if trigger_ip != "unknown" else "unknown"

        conn.execute(
            """INSERT INTO triggers
               (id, harvest_id, canary_token_code, trigger_ip, trigger_time, raw_payload, trigger_geo)
               VALUES (?,?,?,?,?,?,?)""",
            (trigger_id, harvest_row["id"] if harvest_row else None, token_code,
             trigger_ip, now, json.dumps(payload), geo),
        )
        if harvest_row:
            conn.execute("UPDATE harvests SET triggered=1 WHERE id=?", (harvest_row["id"],))

    if harvest_row:
        delta_min = (now - harvest_row["harvested_at"]) / 60
        harvest_time = datetime.fromtimestamp(harvest_row["harvested_at"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        trigger_time = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        msg = (
            "🚨 <b>CANARY TRIGGERED — CORRELATED INCIDENT</b>\n"
            f"Trap: {harvest_row['trap_type']}\n"
            f"Harvested by: {harvest_row['visitor_ip']} ({harvest_row['harvest_geo']})\n"
            f"Harvest time: {harvest_time}\n"
            f"Used from: {trigger_ip} ({geo})\n"
            f"Trigger time: {trigger_time}\n"
            f"Time to use: {delta_min:.1f} min\n"
            f"Harvest ID: {harvest_row['id']}"
        )
    else:
        msg = (
            "🚨 <b>CANARY TRIGGERED — NO MATCHING HARVEST ON RECORD</b>\n"
            f"Token: {token_code}\n"
            f"From: {trigger_ip} ({geo})\n"
            f"Raw payload (truncated): {json.dumps(payload)[:300]}"
        )

    await notify_telegram(msg)
    return {"status": "received"}

# ---------------------------------------------------------------------------
# Dashboard (HTML + JSON API) – top‑notch UI
# ---------------------------------------------------------------------------
def fmt_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def build_console_data(limit: int = 300) -> Dict[str, Any]:
    with db() as conn:
        harvests = conn.execute(
            "SELECT * FROM harvests ORDER BY harvested_at DESC LIMIT ?", (limit,)
        ).fetchall()
        triggers = conn.execute(
            "SELECT * FROM triggers ORDER BY trigger_time DESC LIMIT ?", (limit,)
        ).fetchall()
        total_harvest = conn.execute("SELECT COUNT(*) c FROM harvests").fetchone()["c"]
        total_triggered = conn.execute("SELECT COUNT(*) c FROM harvests WHERE triggered=1").fetchone()["c"]

    trig_by_harvest = {}
    for t in triggers:
        if t["harvest_id"]:
            trig_by_harvest.setdefault(t["harvest_id"], []).append(t)

    incidents = []
    outstanding = []
    for h in harvests:
        matches = trig_by_harvest.get(h["id"], [])
        if matches:
            for t in matches:
                delta_min = (t["trigger_time"] - h["harvested_at"]) / 60
                incidents.append({
                    "harvest_id": h["id"],
                    "trap_type": h["trap_type"],
                    "harvest_ip": h["visitor_ip"],
                    "harvest_geo": h["harvest_geo"],
                    "harvest_time": h["harvested_at"],
                    "harvest_time_str": fmt_iso(h["harvested_at"]),
                    "trigger_ip": t["trigger_ip"],
                    "trigger_geo": t["trigger_geo"],
                    "trigger_time": t["trigger_time"],
                    "trigger_time_str": fmt_iso(t["trigger_time"]),
                    "delta_min": round(delta_min, 1),
                })
        else:
            outstanding.append({
                "harvest_id": h["id"],
                "trap_type": h["trap_type"],
                "harvest_ip": h["visitor_ip"],
                "harvest_geo": h["harvest_geo"],
                "harvest_time": h["harvested_at"],
                "harvest_time_str": fmt_iso(h["harvested_at"]),
            })

    incidents.sort(key=lambda i: i["trigger_time"], reverse=True)

    return {
        "total_harvest": total_harvest,
        "total_triggered": total_triggered,
        "total_outstanding": total_harvest - total_triggered,
        "incidents": incidents,
        "outstanding": outstanding,
        "generated_at": fmt_iso(time.time()),
    }

@app.get("/console/data")
async def console_data(auth: bool = Depends(check_auth)):
    return JSONResponse(build_console_data())

@app.get("/console", response_class=HTMLResponse)
async def dashboard(auth: bool = Depends(check_auth)):
    initial = build_console_data()
    initial_json = json.dumps(initial)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TRIPWIRE // CANARY CORRELATION CONSOLE</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:opsz,wght@14..32,400;14..32,500;14..32,600;14..32,700;14..32,800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #0a0c0f;
      --panel: #111417;
      --panel-2: #181c21;
      --border: #23282e;
      --text: #e2e8f0;
      --muted: #758394;
      --dim: #3d4752;
      --amber: #fbbf24;
      --cyan: #22d3ee;
      --red: #fb7185;
      --green: #4ade80;
      --blue: #60a5fa;
    }}
    * {{ box-sizing: border-box; margin: 0; }}
    html, body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      padding: 0;
      margin: 0;
    }}
    a {{ color: inherit; text-decoration: none; }}
    .wrap {{
      max-width: 1280px;
      margin: 0 auto;
      padding: 32px 24px 64px;
    }}

    /* Top bar */
    .topbar {{
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 28px;
      flex-wrap: wrap;
      gap: 16px;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 14px;
    }}
    .brand .dot {{
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 0 4px rgba(74, 222, 128, 0.15);
      animation: pulse 2.4s ease-in-out infinite;
    }}
    @media (prefers-reduced-motion: reduce) {{ .brand .dot {{ animation: none; }} }}
    @keyframes pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.3; }} }}
    .brand h1 {{
      font-size: 22px;
      font-weight: 800;
      letter-spacing: 0.02em;
      margin: 0;
      background: linear-gradient(135deg, #e2e8f0 60%, #94a3b8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }}
    .eyebrow {{
      font-size: 11px;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      color: var(--amber);
      font-weight: 600;
      margin-bottom: 2px;
    }}
    .meta {{
      text-align: right;
      color: var(--muted);
      font-size: 12px;
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    #refresh-btn {{
      background: var(--panel-2);
      border: 1px solid var(--border);
      color: var(--cyan);
      font-family: inherit;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      padding: 6px 14px;
      cursor: pointer;
      border-radius: 6px;
      transition: all 0.15s;
    }}
    #refresh-btn:hover {{
      border-color: var(--cyan);
      background: var(--border);
    }}
    #refresh-btn:active {{ transform: scale(0.96); }}

    /* Stats */
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 14px;
      margin-bottom: 28px;
    }}
    .stat {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-top: 3px solid var(--stat-color, var(--cyan));
      border-radius: 8px;
      padding: 18px 20px;
    }}
    .stat b {{
      display: block;
      font-size: 32px;
      font-weight: 700;
      font-variant-numeric: tabular-nums;
      letter-spacing: -0.02em;
      color: var(--stat-color, var(--text));
    }}
    .stat span {{
      font-size: 11px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 500;
    }}
    .stat.sprung {{ --stat-color: var(--amber); }}
    .stat.triggered {{ --stat-color: var(--red); }}
    .stat.outstanding {{ --stat-color: var(--cyan); }}

    /* Controls */
    .controls {{
      display: flex;
      gap: 12px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }}
    .controls input, .controls select {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-family: inherit;
      font-size: 13px;
      padding: 10px 14px;
      transition: border 0.15s;
      min-width: 0;
    }}
    .controls input {{
      flex: 1;
      min-width: 200px;
    }}
    .controls input::placeholder {{ color: var(--dim); }}
    .controls input:focus, .controls select:focus {{
      outline: none;
      border-color: var(--cyan);
    }}
    .controls select {{
      cursor: pointer;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%23758394' stroke-width='1.5' fill='none'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 12px center;
      padding-right: 36px;
      appearance: none;
    }}

    .section-label {{
      font-size: 11px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--muted);
      margin: 32px 0 14px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
      font-weight: 600;
    }}

    /* Incident cards */
    .incident {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-left: 4px solid var(--red);
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 12px;
      transition: background 0.1s;
    }}
    .incident:hover {{ background: var(--panel-2); }}
    .trace {{
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
    }}
    .node {{
      flex: 1;
      min-width: 180px;
    }}
    .node .label {{
      font-size: 10px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      margin-bottom: 3px;
      font-weight: 600;
    }}
    .node.harvest .label {{ color: var(--cyan); }}
    .node.trigger .label {{ color: var(--red); }}
    .node .ip {{
      font-size: 15px;
      font-weight: 600;
      font-feature-settings: "tnum";
    }}
    .node .geo {{
      color: var(--muted);
      font-size: 12px;
      margin-top: 2px;
      word-break: break-word;
    }}
    .node .time {{
      color: var(--dim);
      font-size: 11px;
      margin-top: 2px;
    }}
    .link {{
      flex: 0 0 auto;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 4px;
      color: var(--muted);
      font-size: 11px;
      min-width: 80px;
    }}
    .link .line {{
      width: 100%;
      height: 1px;
      background: repeating-linear-gradient(90deg, var(--dim) 0 6px, transparent 6px 11px);
      position: relative;
    }}
    .link .line::after {{
      content: '';
      position: absolute;
      right: -4px;
      top: -3px;
      border: 4px solid transparent;
      border-left-color: var(--dim);
    }}
    .incident-foot {{
      display: flex;
      justify-content: space-between;
      margin-top: 12px;
      padding-top: 10px;
      border-top: 1px solid var(--border);
      font-size: 12px;
      color: var(--muted);
      align-items: center;
      flex-wrap: wrap;
      gap: 6px;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 10px;
      font-size: 10px;
      font-weight: 600;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      border: 1px solid var(--border);
      border-radius: 12px;
      color: var(--amber);
    }}
    .hid {{
      font-family: 'JetBrains Mono', monospace;
      color: var(--dim);
      font-size: 11px;
    }}

    /* Outstanding rows */
    .out-row {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
      font-size: 13px;
      opacity: 0.8;
      flex-wrap: wrap;
    }}
    .out-row:hover {{ background: var(--panel-2); }}
    .out-row .ip {{ font-weight: 500; }}
    .out-row .geo {{ color: var(--muted); font-size: 12px; }}
    .out-row .time {{ color: var(--dim); font-size: 11px; }}

    .empty {{
      border: 1px dashed var(--border);
      border-radius: 8px;
      padding: 48px 20px;
      text-align: center;
      color: var(--muted);
      font-size: 14px;
    }}
    .empty .cursor {{
      display: inline-block;
      width: 10px;
      height: 16px;
      background: var(--green);
      margin-left: 6px;
      animation: pulse 1s steps(1) infinite;
      vertical-align: text-bottom;
    }}

    /* Scrollbar */
    ::-webkit-scrollbar {{ height: 8px; width: 8px; }}
    ::-webkit-scrollbar-track {{ background: var(--bg); }}
    ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 4px; }}
    ::-webkit-scrollbar-thumb:hover {{ background: var(--dim); }}

    /* Responsive */
    @media (max-width: 640px) {{
      .wrap {{ padding: 20px 16px; }}
      .topbar {{ flex-direction: column; align-items: stretch; }}
      .meta {{ justify-content: flex-end; }}
      .stats {{ grid-template-columns: 1fr 1fr; }}
      .trace {{ flex-direction: column; align-items: stretch; }}
      .link {{ flex-direction: row; min-width: unset; }}
      .link .line {{ display: none; }}
      .incident-foot {{ flex-direction: column; align-items: flex-start; }}
      .controls input {{ min-width: 120px; }}
    }}
  </style>
</head>
<body>
<div class="wrap">

  <div class="topbar">
    <div>
      <div class="eyebrow">AWS Canary Correlation Console</div>
      <div class="brand"><span class="dot" aria-hidden="true"></span><h1>TRIPWIRE</h1></div>
    </div>
    <div class="meta">
      Last updated <span id="last-updated">{initial['generated_at']}</span> UTC
      <button id="refresh-btn" onclick="loadData()">⟳ Refresh</button>
    </div>
  </div>

  <div class="stats">
    <div class="stat sprung"><b id="stat-sprung">{initial['total_harvest']}</b><span>Traps Sprung</span></div>
    <div class="stat triggered"><b id="stat-triggered">{initial['total_triggered']}</b><span>Keys Triggered</span></div>
    <div class="stat outstanding"><b id="stat-outstanding">{initial['total_outstanding']}</b><span>Outstanding</span></div>
  </div>

  <div class="controls">
    <input id="search" type="text" placeholder="Filter by IP, ASN, trap type, or harvest ID..." oninput="render()">
    <select id="trap-filter" onchange="render()">
      <option value="">All trap types</option>
      <option value="env_file">.env</option>
      <option value="kubeconfig">kubeconfig</option>
      <option value="cloud_keys">cloud-keys.json</option>
    </select>
  </div>

  <div class="section-label">Correlated Incidents — Key Used After Harvest</div>
  <div id="incidents"></div>

  <div class="section-label">Outstanding — Minted, Not Yet Triggered</div>
  <div id="outstanding"></div>

</div>

<script>
let DATA = {initial_json};

function esc(s) {{
  return String(s ?? '').replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[c]);
}}

function matches(item, q, trapFilter) {{
  if (trapFilter && item.trap_type !== trapFilter) return false;
  if (!q) return true;
  q = q.toLowerCase();
  return Object.values(item).some(v => String(v ?? '').toLowerCase().includes(q));
}}

function render() {{
  const q = document.getElementById('search').value.trim();
  const trapFilter = document.getElementById('trap-filter').value;

  document.getElementById('stat-sprung').textContent = DATA.total_harvest;
  document.getElementById('stat-triggered').textContent = DATA.total_triggered;
  document.getElementById('stat-outstanding').textContent = DATA.total_outstanding;
  document.getElementById('last-updated').textContent = DATA.generated_at;

  const incidents = DATA.incidents.filter(i => matches(i, q, trapFilter));
  const incidentsEl = document.getElementById('incidents');
  if (incidents.length === 0) {{
    incidentsEl.innerHTML = `<div class="empty">No correlated incidents yet — this is where a harvested key showing up in real AWS traffic will land.<span class="cursor"></span></div>`;
  }} else {{
    incidentsEl.innerHTML = incidents.map(i => `
      <div class="incident">
        <div class="trace">
          <div class="node harvest">
            <div class="label">Harvested by</div>
            <div class="ip">${{esc(i.harvest_ip)}}</div>
            <div class="geo">${{esc(i.harvest_geo)}}</div>
            <div class="time">${{esc(i.harvest_time_str)}} UTC</div>
          </div>
          <div class="link"><div class="line"></div>${{i.delta_min}} min later</div>
          <div class="node trigger">
            <div class="label">Used from</div>
            <div class="ip">${{esc(i.trigger_ip)}}</div>
            <div class="geo">${{esc(i.trigger_geo)}}</div>
            <div class="time">${{esc(i.trigger_time_str)}} UTC</div>
          </div>
        </div>
        <div class="incident-foot">
          <span class="badge">${{esc(i.trap_type)}}</span>
          <span class="hid">harvest ${{esc(i.harvest_id)}}</span>
        </div>
      </div>
    `).join('');
  }}

  const outstanding = DATA.outstanding.filter(i => matches(i, q, trapFilter));
  const outEl = document.getElementById('outstanding');
  if (outstanding.length === 0) {{
    outEl.innerHTML = `<div class="empty">Nothing outstanding.</div>`;
  }} else {{
    outEl.innerHTML = outstanding.map(o => `
      <div class="out-row">
        <span class="badge">${{esc(o.trap_type)}}</span>
        <span class="ip">${{esc(o.harvest_ip)}}</span>
        <span class="geo">${{esc(o.harvest_geo)}}</span>
        <span class="time">${{esc(o.harvest_time_str)}} UTC</span>
        <span class="hid">${{esc(o.harvest_id)}}</span>
      </div>
    `).join('');
  }}
}}

async function loadData() {{
  try {{
    const res = await fetch('/console/data', {{ credentials: 'same-origin' }});
    if (!res.ok) return;
    DATA = await res.json();
    render();
  }} catch (e) {{ /* silent — keep last known state on transient network errors */ }}
}}

render();
setInterval(loadData, 20000);
</script>
</body>
</html>"""
    return HTMLResponse(html)

# ---------------------------------------------------------------------------
# Main landing page – Secure Crypto Vault (top‑notch decoy)
# ---------------------------------------------------------------------------
VAULT_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Quantum Vault · Secure Digital Asset Treasury</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:opsz,wght@14..32,300;14..32,400;14..32,500;14..32,600;14..32,700;14..32,800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #06080a;
      --panel: rgba(17, 23, 30, 0.75);
      --border: rgba(56, 66, 80, 0.4);
      --text: #eef2f6;
      --muted: #8a9aa8;
      --gold: #f7b731;
      --gold-glow: rgba(247, 183, 49, 0.25);
      --cyan: #2dd4ea;
      --green: #4ade80;
      --red: #fb7185;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      background-image: radial-gradient(ellipse at 20% 50%, rgba(45, 212, 234, 0.06) 0%, transparent 70%),
                        radial-gradient(ellipse at 80% 20%, rgba(247, 183, 49, 0.05) 0%, transparent 60%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: var(--text);
      padding: 20px;
      line-height: 1.6;
    }
    .vault {
      max-width: 1200px;
      width: 100%;
      background: var(--panel);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--border);
      border-radius: 32px;
      padding: 40px 44px;
      box-shadow: 0 30px 80px rgba(0,0,0,0.7), 0 0 0 1px rgba(247, 183, 49, 0.08) inset;
      transition: all 0.2s;
    }
    @media (max-width: 640px) {
      .vault { padding: 24px 18px; border-radius: 20px; }
    }

    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 28px;
    }
    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .logo-icon {
      width: 42px;
      height: 42px;
      background: linear-gradient(135deg, var(--gold), #d48c2c);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 20px;
      font-weight: 800;
      color: #0a0c0f;
      box-shadow: 0 0 20px var(--gold-glow);
    }
    .logo h1 {
      font-size: 22px;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(to right, #fff, #b0c4d9);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .logo span {
      font-size: 12px;
      font-weight: 400;
      color: var(--muted);
      letter-spacing: 0.1em;
      -webkit-text-fill-color: var(--muted);
      background: none;
    }
    .status-badge {
      display: flex;
      align-items: center;
      gap: 8px;
      background: rgba(74, 222, 128, 0.12);
      border: 1px solid rgba(74, 222, 128, 0.2);
      padding: 6px 16px 6px 12px;
      border-radius: 40px;
      font-size: 13px;
      font-weight: 500;
      color: var(--green);
    }
    .status-badge .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--green);
      animation: pulse-dot 2s ease-in-out infinite;
    }
    @keyframes pulse-dot { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }

    .grid-2 {
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 32px;
      margin-bottom: 32px;
    }
    @media (max-width: 860px) {
      .grid-2 { grid-template-columns: 1fr; gap: 24px; }
    }

    .login-card {
      background: rgba(0,0,0,0.25);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 28px 30px;
    }
    .login-card h2 {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 6px;
    }
    .login-card p {
      color: var(--muted);
      font-size: 14px;
      margin-bottom: 20px;
    }
    .input-group {
      margin-bottom: 16px;
    }
    .input-group label {
      display: block;
      font-size: 12px;
      font-weight: 500;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 4px;
    }
    .input-group input {
      width: 100%;
      background: rgba(0,0,0,0.3);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 12px 16px;
      font-size: 15px;
      color: var(--text);
      transition: border 0.15s;
      font-family: inherit;
    }
    .input-group input:focus {
      outline: none;
      border-color: var(--gold);
      box-shadow: 0 0 0 3px var(--gold-glow);
    }
    .input-group input::placeholder { color: #4a5a6a; }
    .login-btn {
      width: 100%;
      background: linear-gradient(135deg, var(--gold), #d48c2c);
      border: none;
      border-radius: 12px;
      padding: 14px;
      font-size: 16px;
      font-weight: 700;
      color: #0a0c0f;
      cursor: pointer;
      transition: all 0.15s;
      font-family: inherit;
      letter-spacing: 0.02em;
      margin-top: 8px;
    }
    .login-btn:hover { transform: scale(1.01); box-shadow: 0 0 30px var(--gold-glow); }
    .login-btn:active { transform: scale(0.97); }
    .login-foot {
      display: flex;
      justify-content: space-between;
      font-size: 13px;
      color: var(--muted);
      margin-top: 16px;
    }
    .login-foot a { color: var(--cyan); text-decoration: none; }
    .login-foot a:hover { text-decoration: underline; }

    .tx-panel {
      background: rgba(0,0,0,0.25);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 20px 24px;
    }
    .tx-panel .head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }
    .tx-panel .head h3 {
      font-size: 15px;
      font-weight: 600;
    }
    .tx-panel .head .tag {
      font-size: 11px;
      color: var(--muted);
      background: rgba(255,255,255,0.04);
      padding: 2px 12px;
      border-radius: 40px;
      border: 1px solid var(--border);
    }
    .tx-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .tx-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 0;
      border-bottom: 1px solid rgba(255,255,255,0.04);
      font-size: 13px;
    }
    .tx-item:last-child { border-bottom: none; }
    .tx-item .asset { font-weight: 600; color: var(--gold); }
    .tx-item .addr { color: var(--muted); font-family: 'JetBrains Mono', monospace; font-size: 12px; }
    .tx-item .amount { font-weight: 600; }
    .tx-item .amount.positive { color: var(--green); }
    .tx-item .amount.negative { color: var(--red); }
    .tx-item .time { color: var(--muted); font-size: 11px; }

    .balance-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(0,0,0,0.2);
      border-radius: 16px;
      padding: 14px 22px;
      margin-bottom: 20px;
      border: 1px solid var(--border);
    }
    .balance-row .label { color: var(--muted); font-size: 13px; }
    .balance-row .value { font-size: 26px; font-weight: 700; letter-spacing: -0.02em; }
    .balance-row .value .currency { font-size: 16px; font-weight: 400; color: var(--muted); margin-left: 6px; }

    .footer {
      border-top: 1px solid var(--border);
      padding-top: 18px;
      margin-top: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      font-size: 12px;
      color: var(--muted);
    }
    .footer .badges {
      display: flex;
      gap: 12px;
    }
    .footer .badges span {
      background: rgba(255,255,255,0.04);
      padding: 2px 12px;
      border-radius: 40px;
      border: 1px solid var(--border);
      font-size: 10px;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .footer a { color: var(--cyan); text-decoration: none; }
    .footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>
<div class="vault">

  <div class="header">
    <div class="logo">
      <div class="logo-icon">Q</div>
      <div>
        <h1>Quantum Vault <span>· Secure Treasury</span></h1>
      </div>
    </div>
    <div class="status-badge">
      <span class="dot"></span> All systems operational
    </div>
  </div>

  <div class="balance-row">
    <span class="label">Total Portfolio Balance</span>
    <span class="value">$14,287,340.18 <span class="currency">USD</span></span>
  </div>

  <div class="grid-2">
    <!-- Login / Access Panel -->
    <div class="login-card">
      <h2>🔐 Secure Vault Access</h2>
      <p>Authenticate to manage digital assets and initiate transactions.</p>
      <form onsubmit="event.preventDefault(); alert('Access denied — this is a secured vault. Please contact your administrator.');">
        <div class="input-group">
          <label for="email">Email Address</label>
          <input type="email" id="email" placeholder="admin@vault.internal" value="admin@vault.internal">
        </div>
        <div class="input-group">
          <label for="password">Password</label>
          <input type="password" id="password" placeholder="••••••••" value="••••••••">
        </div>
        <button type="submit" class="login-btn">Unlock Vault</button>
        <div class="login-foot">
          <a href="#">Forgot credentials?</a>
          <a href="#">Request access</a>
        </div>
      </form>
    </div>

    <!-- Recent Transactions -->
    <div class="tx-panel">
      <div class="head">
        <h3>Recent Transactions</h3>
        <span class="tag">Live</span>
      </div>
      <div class="tx-list">
        <div class="tx-item">
          <span class="asset">BTC</span>
          <span class="addr">1A1zP1eP…QGefi2D</span>
          <span class="amount positive">+0.3421</span>
          <span class="time">3 min ago</span>
        </div>
        <div class="tx-item">
          <span class="asset">ETH</span>
          <span class="addr">0x742d35…663b8f</span>
          <span class="amount negative">-12.50</span>
          <span class="time">18 min ago</span>
        </div>
        <div class="tx-item">
          <span class="asset">USDC</span>
          <span class="addr">0xab5801…b2c3d4</span>
          <span class="amount positive">+5,000.00</span>
          <span class="time">1h ago</span>
        </div>
        <div class="tx-item">
          <span class="asset">SOL</span>
          <span class="addr">E8iUqN…pLm9Q</span>
          <span class="amount positive">+256.73</span>
          <span class="time">2h ago</span>
        </div>
        <div class="tx-item">
          <span class="asset">XRP</span>
          <span class="addr">r3kmLJ…k4J9X</span>
          <span class="amount negative">-1,200.00</span>
          <span class="time">3h ago</span>
        </div>
      </div>
    </div>
  </div>

  <div class="footer">
    <span>© 2026 Quantum Vault · All rights reserved.</span>
    <div class="badges">
      <span>🔒 AES‑256</span>
      <span>🛡️ SOC 2</span>
      <span>⚡ 99.99% uptime</span>
    </div>
    <span><a href="/console">Admin Console</a> · <a href="#">Privacy</a></span>
  </div>

</div>

<!-- Simple deception: if someone tries to click on the login button, it shows a message, but also we could log the attempt in the backend? Not necessary for this decoy. -->
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(VAULT_PAGE)

# ---------------------------------------------------------------------------
# Health endpoint – used for monitoring and keep‑alive
# ---------------------------------------------------------------------------
@app.get("/ping")
async def ping():
    return {"status": "alive"}

@app.get("/health")
async def health():
    return {"status": "ok", "db": DB_PATH}

# ---------------------------------------------------------------------------
# Keep‑alive background task – prevents Render from sleeping
# ---------------------------------------------------------------------------
async def keep_alive():
    """
    Periodically ping the service itself to keep the Render instance awake.
    Runs every 4 minutes (less than the 5‑minute idle timeout on free tier).
    """
    if not BASE_URL:
        log.warning("BASE_URL not set, keep‑alive disabled.")
        return

    ping_url = f"{BASE_URL}/ping"
    while True:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(ping_url)
                if resp.status_code == 200:
                    log.debug("Keep‑alive ping successful.")
                else:
                    log.warning("Keep‑alive ping returned %s", resp.status_code)
        except Exception as e:
            log.warning("Keep‑alive ping failed: %s", e)
        await asyncio.sleep(240)  # 4 minutes

# ---------------------------------------------------------------------------
# Admin / test endpoints
# ---------------------------------------------------------------------------
@app.get("/admin/test-mint")
async def test_mint(auth: bool = Depends(check_auth)):
    hid = secrets.token_hex(8)
    memo = f"tripwire:manual_test:{hid[:8]}"
    payload = {"type": "aws_keys", "memo": memo}
    if BASE_URL:
        payload["webhook_url"] = f"{BASE_URL}/webhook/canarytoken"

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(CANARYTOKENS_GENERATE_URL, data=payload)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        return JSONResponse(
            {"ok": False, "error": f"Request failed: {str(e)}", "raw": None},
            status_code=502,
        )

    access_key_id = data.get("access_key_id")
    secret_access_key = data.get("secret_access_key")
    token_code = data.get("canarytoken") or data.get("token")

    if not access_key_id or not secret_access_key:
        return JSONResponse(
            {
                "ok": False,
                "error": "Unexpected response shape – missing access_key_id or secret_access_key",
                "raw_response": data,
            },
            status_code=502,
        )

    return {
        "ok": True,
        "result": {
            "token_code": token_code,
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "memo": memo,
        }
    }

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))

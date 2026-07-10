"""
TRIPWIRE — per-visitor AWS canary honeypot
--------------------------------------------------------------------
Single-file FastAPI service. Serves fake credential files (.env,
kubeconfig, cloud-keys.json). Every distinct visitor who pulls a trap
file gets their own live-looking AWS key, minted on the fly via
canarytokens.org's free public API (no signup, no AWS account, no
API key required on our side). If that key is ever used against AWS
from anywhere, canarytokens.org posts a webhook back here, and this
service correlates the trigger to the original harvest event and
fires a Telegram alert naming both ends.

Persistence: SQLite on a Render persistent disk (single instance only —
do not scale this service horizontally without moving to Postgres,
since SQLite on a disk is not shared across instances).
"""

import os
import json
import time
import hashlib
import secrets
import base64
import logging
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Optional

import httpx
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import PlainTextResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("tripwire")

# ---------------------------------------------------------------------------
# Config (all via Render environment variables — no secrets in code)
# ---------------------------------------------------------------------------
DB_PATH = os.environ.get("DB_PATH", "/var/data/tripwire.db")
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/")  # e.g. https://tripwire-console.onrender.com
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASS = os.environ.get("DASHBOARD_PASS", "")
MINT_DEDUPE_HOURS = float(os.environ.get("MINT_DEDUPE_HOURS", "24"))

CANARYTOKENS_GENERATE_URL = "https://canarytokens.org/generate"
IP_GEO_URL = "http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,hosting,proxy"

# AWS's own published example key — used ONLY as a last-resort fallback if
# minting fails, so a trap never serves a broken file. Not a real credential,
# not monitored, will never phone home.
FALLBACK_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
FALLBACK_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

sqlite_import_ok = True
import sqlite3  # noqa: E402

app = FastAPI(title="Tripwire Console", docs_url=None, redoc_url=None)
security = HTTPBasic()


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
@contextmanager
def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
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


async def mint_canary(harvest_id: str, trap_type: str) -> Optional[dict]:
    """
    Mint a fresh AWS Keys Canarytoken via canarytokens.org's free public
    API. No auth token needed for this endpoint. If the response shape
    doesn't match what we expect, we log the raw body so it's easy to
    diagnose against whatever the live API actually returns — hit
    /admin/test-mint right after deploy to confirm this works before any
    real trap depends on it.
    """
    memo = f"tripwire:{trap_type}:{harvest_id[:8]}"
    payload = {"type": "aws_keys", "memo": memo}
    if BASE_URL:
        payload["webhook_url"] = f"{BASE_URL}/webhook/canarytoken"

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(CANARYTOKENS_GENERATE_URL, data=payload)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        log.error("mint_canary request failed: %s", e)
        return None

    access_key_id = data.get("access_key_id")
    secret_access_key = data.get("secret_access_key")
    token_code = data.get("canarytoken") or data.get("token")

    if not access_key_id or not secret_access_key:
        log.error("mint_canary unexpected response shape, raw=%s", json.dumps(data)[:1000])
        return None

    return {
        "token_code": token_code,
        "access_key_id": access_key_id,
        "secret_access_key": secret_access_key,
        "memo": memo,
    }


async def handle_trap(request: Request, trap_type: str) -> dict:
    """
    Shared harvest logic for every trap endpoint. Reuses an existing
    untriggered key for the same IP + trap type within MINT_DEDUPE_HOURS
    (so a scanner re-crawling the same path repeatedly doesn't burn a
    fresh key every request) and mints a new one otherwise.
    """
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
    # Classic bait: scanners and crawlers that parse robots.txt for
    # "disallowed" paths often go straight for them.
    return PlainTextResponse(
        "User-agent: *\n"
        "Disallow: /backup/\n"
        "Disallow: /.env\n"
        "Disallow: /.kube/\n"
        "Disallow: /kubeconfig.yaml\n"
    )


# ---------------------------------------------------------------------------
# Webhook receiver — canarytokens.org calls this when a minted key is used
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
# Dashboard
# ---------------------------------------------------------------------------
@app.get("/console", response_class=HTMLResponse)
async def dashboard(auth: bool = Depends(check_auth)):
    with db() as conn:
        harvests = conn.execute("SELECT * FROM harvests ORDER BY harvested_at DESC LIMIT 300").fetchall()
        triggers = conn.execute("SELECT * FROM triggers ORDER BY trigger_time DESC LIMIT 300").fetchall()
        total_harvest = conn.execute("SELECT COUNT(*) c FROM harvests").fetchone()["c"]
        total_triggered = conn.execute("SELECT COUNT(*) c FROM harvests WHERE triggered=1").fetchone()["c"]

    trig_by_harvest = {}
    for t in triggers:
        if t["harvest_id"]:
            trig_by_harvest.setdefault(t["harvest_id"], []).append(t)

    def fmt(ts):
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    rows_html = ""
    for h in harvests:
        matches = trig_by_harvest.get(h["id"], [])
        if matches:
            for t in matches:
                delta = (t["trigger_time"] - h["harvested_at"]) / 60
                rows_html += (
                    "<tr class=\"hit\">"
                    f"<td>{h['trap_type']}</td>"
                    f"<td>{h['visitor_ip']}<br><span class=\"geo\">{h['harvest_geo']}</span></td>"
                    f"<td>{fmt(h['harvested_at'])}</td>"
                    f"<td>{t['trigger_ip']}<br><span class=\"geo\">{t['trigger_geo']}</span></td>"
                    f"<td>{fmt(t['trigger_time'])}</td>"
                    f"<td>{delta:.1f} min</td>"
                    f"<td class=\"mono\">{h['id']}</td></tr>"
                )
        else:
            rows_html += (
                "<tr>"
                f"<td>{h['trap_type']}</td>"
                f"<td>{h['visitor_ip']}<br><span class=\"geo\">{h['harvest_geo']}</span></td>"
                f"<td>{fmt(h['harvested_at'])}</td>"
                "<td>—</td><td>—</td><td>—</td>"
                f"<td class=\"mono\">{h['id']}</td></tr>"
            )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>TRIPWIRE // CONSOLE</title>
<style>
  :root {{ --bg:#0a0d0f; --panel:#111519; --border:#1f2937; --amber:#ffb000; --cyan:#00e5ff; --red:#ff5c5c; --text:#c9d1d9; }}
  * {{ box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--text); font-family:'Courier New', ui-monospace, monospace; margin:0; padding:28px; }}
  h1 {{ color:var(--amber); letter-spacing:2px; font-size:19px; border-bottom:1px solid var(--border); padding-bottom:12px; font-weight:600; }}
  .stats {{ display:flex; gap:14px; margin:18px 0 24px; }}
  .stat {{ background:var(--panel); border:1px solid var(--border); padding:12px 22px; }}
  .stat b {{ display:block; font-size:26px; color:var(--cyan); }}
  .stat span {{ font-size:11px; letter-spacing:1px; color:#6b7280; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th {{ text-align:left; color:var(--amber); border-bottom:1px solid var(--border); padding:8px; text-transform:uppercase; font-size:11px; letter-spacing:1px; }}
  td {{ padding:8px; border-bottom:1px solid #1a1e22; vertical-align:top; }}
  tr.hit td {{ background:#1a0d0d; color:var(--red); }}
  .geo {{ color:#6b7280; font-size:11px; }}
  .mono {{ font-family:monospace; font-size:11px; color:#6b7280; }}
</style></head>
<body>
<h1>&gt;&gt; TRIPWIRE // AWS CANARY CONSOLE</h1>
<div class="stats">
  <div class="stat"><b>{total_harvest}</b><span>TRAPS SPRUNG</span></div>
  <div class="stat"><b>{total_triggered}</b><span>KEYS TRIGGERED</span></div>
  <div class="stat"><b>{total_harvest - total_triggered}</b><span>OUTSTANDING</span></div>
</div>
<table>
<tr><th>Trap</th><th>Harvested By</th><th>Harvest Time (UTC)</th><th>Triggered From</th><th>Trigger Time (UTC)</th><th>&Delta;</th><th>Harvest ID</th></tr>
{rows_html}
</table>
</body></html>"""
    return HTMLResponse(html)


@app.get("/admin/test-mint")
async def test_mint(auth: bool = Depends(check_auth)):
    """
    Manually trigger a mint against canarytokens.org and return the raw
    result. Use this immediately after deploying to confirm the live API
    response shape matches what mint_canary() expects.
    """
    hid = secrets.token_hex(8)
    result = await mint_canary(hid, "manual_test")
    if not result:
        return JSONResponse(
            {"ok": False, "error": "Mint failed or unexpected response shape — check service logs for the raw body."},
            status_code=502,
        )
    return {"ok": True, "result": result}


@app.get("/", response_class=PlainTextResponse)
async def root():
    return PlainTextResponse("ok", status_code=200)

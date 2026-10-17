#!/usr/bin/env python3
"""Qwen CLI OAuth device flow (matches @qwen-code/qwen-code 0.17.1 qwenOAuth2.ts).

Phase 1 (--start): request a device code, print the verification URL + user code.
Phase 2 (--poll) : poll the token endpoint, then write ~/.qwen/oauth_creds.json
                   in the exact schema Hermes' qwen-oauth credential pool reads.

Endpoints / constants below are taken verbatim from the installed Qwen CLI
bundle and from hermes_cli/auth_constants.py.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

CLIENT_ID = "f0304373b74a44d2b584a3fb70ca9e56"
SCOPE = "openid profile email model.completion"
GRANT = "urn:ietf:params:oauth:grant-type:device_code"
DEVICE_URL = "https://chat.qwen.ai/api/v1/oauth2/device/code"
TOKEN_URL = "https://chat.qwen.ai/api/v1/oauth2/token"
CREDS = Path.home() / ".qwen" / "oauth_creds.json"
STATE = Path(os.environ.get("TMPDIR", "/tmp")).joinpath("qwen-device-auth.json")

FORM = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
    # urllib's default UA trips Qwen's edge (returns an HTML challenge page with
    # HTTP 200 instead of JSON); curl's default UA works, so mirror a normal client.
    "User-Agent": "curl/8.7.1",
    "Accept-Language": "en-US,en;q=0.9",
}


def form(data: dict) -> bytes:
    return urllib.parse.urlencode(data).encode()


def post(url: str, data: dict, extra: dict | None = None) -> tuple[int, dict]:
    headers = dict(FORM)
    if extra:
        headers.update(extra)
    req = urllib.request.Request(url, data=form(data), headers=headers, method="POST")
    ctx = ssl.create_default_context()
    last_raw = ""
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
                raw = r.read().decode(errors="replace")
                try:
                    return r.status, json.loads(raw or "{}")
                except json.JSONDecodeError:
                    last_raw = raw  # e.g. an HTML anti-bot page — retry
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            try:
                return e.code, json.loads(raw or "{}")
            except Exception:
                return e.code, {"raw": raw}
        time.sleep(1.5 * (attempt + 1))
    return 200, {"raw": last_raw, "error": "non_json_response"}


def pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


def save_state(d: dict[str, object]) -> None:
    STATE.write_text(json.dumps(d), encoding="utf-8")
    os.chmod(STATE, 0o600)


def phase_start() -> int:
    verifier, challenge = pkce()
    status, data = post(
        DEVICE_URL,
        {
            "client_id": CLIENT_ID,
            "scope": SCOPE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        {"x-request-id": str(uuid.uuid4())},
    )
    if status != 200 or "device_code" not in data:
        print(f"device authorization FAILED http={status} body={json.dumps(data)[:400]}")
        return 1
    data["code_verifier"] = verifier
    data["requested_at"] = time.time()
    save_state(data)
    uri = data.get("verification_uri_complete") or data.get("verification_uri") or ""
    print("QWEN_DEVICE_FLOW_STARTED")
    print(f"verification_uri : {data.get('verification_uri')}")
    print(f"user_code        : {data.get('user_code')}")
    print(f"open_this        : {uri}")
    print(f"expires_in_s     : {data.get('expires_in')}")
    print(f"poll_interval_s  : {data.get('interval', 5)}")
    return 0


def register_with_hermes() -> int:
    """Hand the freshly written creds to Hermes' pooled-credential store."""
    import shutil
    import subprocess

    hermes = shutil.which("hermes")
    if not hermes:
        print("hermes CLI not on PATH — run `hermes auth add qwen-oauth` yourself")
        return 1
    print(f"registering       : {hermes} auth add qwen-oauth", flush=True)
    r = subprocess.run([hermes, "auth", "add", "qwen-oauth"], capture_output=True, text=True, timeout=180)
    out = (r.stdout + r.stderr).strip()
    print(f"hermes exit={r.returncode}: {out[:800]}", flush=True)
    return r.returncode


def phase_poll(max_wait: int = 900, register: bool = False) -> int:
    if not STATE.exists():
        print("no pending device flow (run --start first)")
        return 1
    data = json.loads(STATE.read_text(encoding="utf-8"))
    device_code = data["device_code"]
    verifier = data["code_verifier"]
    interval = int(data.get("interval") or 5)
    deadline = data.get("requested_at", time.time()) + min(max_wait, int(data.get("expires_in") or 900)) - 15

    while time.time() < deadline:
        status, body = post(
            TOKEN_URL,
            {
                "grant_type": GRANT,
                "client_id": CLIENT_ID,
                "device_code": device_code,
                "code_verifier": verifier,
            },
        )
        if status == 200 and body.get("access_token"):
            expires_in = int(body.get("expires_in") or 3600)
            creds = {
                "access_token": body["access_token"],
                "token_type": body.get("token_type", "Bearer"),
                "refresh_token": body.get("refresh_token", ""),
                "resource_url": body.get("resource_url"),
                "expiry_date": int(time.time() * 1000) + expires_in * 1000,
            }
            for k in ("id_token", "account_id", "email"):
                if body.get(k):
                    creds[k] = body[k]
            CREDS.parent.mkdir(parents=True, exist_ok=True)
            tmp = CREDS.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(creds, indent=2, sort_keys=True), encoding="utf-8")
            os.chmod(tmp, 0o600)
            tmp.replace(CREDS)
            try:
                STATE.unlink()
            except OSError:
                pass
            print("QWEN_DEVICE_FLOW_OK")
            print(f"creds_written    : {CREDS} (mode 0600)")
            print(f"token_type       : {creds['token_type']}  expires_in={expires_in}s")
            print(f"has_refresh      : {bool(creds['refresh_token'])}")
            if register:
                return register_with_hermes()
            return 0
        err = body.get("error")
        if status in (400, 428) and err in ("authorization_pending", "slow_down", None):
            if err == "slow_down":
                interval += 5
            print(f"… pending ({err or 'authorization_pending'})", flush=True)
            time.sleep(interval)
            continue
        print(f"token poll FAILED http={status} error={err} desc={body.get('error_description')}")
        return 1
    print("token poll TIMED OUT (device code expired) — re-run with --start")
    return 1


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "--start"
    if mode == "--start":
        sys.exit(phase_start())
    if mode in ("--poll", "--poll-register"):
        sys.exit(phase_poll(register=(mode == "--poll-register")))
    print(__doc__)
    sys.exit(2)

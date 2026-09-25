#!/usr/bin/env python3
"""
grok2api-small auto-reauth watchdog.

Polls grok2api-small admin API for accounts with auth_status='reauthRequired'.
When found, uses SSO cookie + device_mint.py to obtain fresh OAuth tokens,
then updates the account via admin API.

Usage:
  python3 reauth_watchdog.py [--check]   # one-shot check
  python3 reauth_watchdog.py [--loop]    # continuous loop (for cron, use --check)

Requires:
  - grok2api-small running on http://127.0.0.1:8792
  - device_mint.py in ~/apps/grok-register-xinxin/
  - SSO cookies in ~/apps/grok-register-xinxin/keys/accounts.txt
  - DISPLAY=:99 + Xvfb for Patchright browser
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

# Config
GROK2API_URL = os.environ.get("GROK2API_URL", "http://127.0.0.1:8792")
GROK_REGISTER_DIR = os.path.expanduser("~/apps/grok-register-xinxin")
DEVICE_MINT = os.path.join(GROK_REGISTER_DIR, "device_mint.py")
ACCOUNTS_FILE = os.path.join(GROK_REGISTER_DIR, "keys", "accounts.txt")
AUTHS_DIR = os.path.join(GROK_REGISTER_DIR, "keys", "auths")
VENV_PYTHON = os.path.join(GROK_REGISTER_DIR, ".venv", "bin", "python")
CHECK_INTERVAL = int(os.environ.get("REAUTH_CHECK_INTERVAL", "600"))  # 10 min


def list_reauth_accounts():
    """List accounts with auth_status='reauthRequired' from grok2api-small."""
    req = urllib.request.Request(f"{GROK2API_URL}/api/admin/reauth")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def list_all_accounts():
    """List all accounts from grok2api-small."""
    req = urllib.request.Request(f"{GROK2API_URL}/api/admin/accounts")
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def load_sso_map():
    """Load email → SSO cookie mapping from accounts.txt."""
    mapping = {}
    if not os.path.exists(ACCOUNTS_FILE):
        return mapping
    with open(ACCOUNTS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 3:
                email = parts[0]
                sso = parts[2]
                if len(sso) >= 100:
                    mapping[email] = sso
    return mapping


def run_device_mint(email, sso_cookie):
    """Run device_mint.py to get fresh OAuth tokens via SSO → Device Flow."""
    env = os.environ.copy()
    env["DISPLAY"] = ":99"
    env["GROK_PROXY"] = os.environ.get("GROK_PROXY", "http://127.0.0.1:8081")
    cmd = [VENV_PYTHON, "-u", DEVICE_MINT, email]
    print(f"  Running device_mint for {email}...")
    started_at = time.time()
    try:
        result = subprocess.run(
            cmd, cwd=GROK_REGISTER_DIR, env=env,
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        print(f"  device_mint TIMED OUT after 120s for {email}")
        return None
    except Exception as e:
        print(f"  device_mint EXCEPTION for {email}: {e}")
        return None
    if result.returncode != 0:
        print(f"  device_mint FAILED (exit {result.returncode})")
        print(f"  stderr: {result.stderr[-500:]}")
        return None
    # device_mint.py exits 0 even when minting fails (prints ❌ 失败).
    # Verify the success marker, otherwise we'd re-import a STALE auth file.
    if "\u2705 \u6210\u529f" not in result.stdout:
        print(f"  device_mint exited 0 but did NOT mint (no success marker). Last output:")
        print(f"  {result.stdout.strip()[-400:]}")
        return None
    # Find the auth file
    safe_email = email.replace("@", "_").replace(".", "_")
    auth_file = os.path.join(AUTHS_DIR, f"xai-{safe_email}.json")
    if not os.path.exists(auth_file):
        print(f"  Auth file not found: {auth_file}")
        return None
    # Guard against importing a stale token: the file must have been
    # written during THIS run (device_mint may fail silently and leave
    # the old file untouched).
    if os.path.getmtime(auth_file) < started_at:
        print(f"  Auth file is STALE (not rewritten this run) — refusing to import old token.")
        return None
    with open(auth_file) as f:
        return json.load(f)


def reauth_account(account_id, auth_data):
    """Update account tokens in grok2api-small after device_mint."""
    payload = json.dumps({
        "account_id": account_id,
        "access_token": auth_data["access_token"],
        "refresh_token": auth_data["refresh_token"],
        "name": auth_data.get("email", ""),
        "email": auth_data.get("email", ""),
    }).encode()
    req = urllib.request.Request(
        f"{GROK2API_URL}/api/admin/reauth",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            print(f"  Reauth response: {data}")
            return True
    except urllib.error.HTTPError as e:
        print(f"  Reauth failed: {e.code} {e.read().decode(errors='replace')[:200]}")
        return False


def check_and_reauth():
    """One-shot check: find reauthRequired accounts and re-auth them."""
    print(f"[{time.strftime('%H:%M:%S')}] Checking for reauthRequired accounts...")
    try:
        reauth_needed = list_reauth_accounts()
    except Exception as e:
        print(f"  Failed to list reauthRequired accounts: {e}")
        return 0

    sso_map = load_sso_map()

    if not reauth_needed:
        try:
            all_accounts = list_all_accounts()
            active = [a for a in all_accounts if a.get("auth_status") == "active"]
            print(f"  All good. {len(active)} active, 0 reauthRequired.")
        except Exception:
            print(f"  All good. 0 reauthRequired.")
        return 0

    print(f"  Found {len(reauth_needed)} reauthRequired account(s):")
    reauthed = 0
    for acct in reauth_needed:
        email = acct.get("email", "")
        account_id = acct.get("id")
        print(f"  - {email} (id={account_id})")
        sso = sso_map.get(email)
        if not sso:
            print(f"    No SSO cookie found for {email}, skipping.")
            continue
        auth_data = run_device_mint(email, sso)
        if not auth_data:
            print(f"    device_mint failed for {email}.")
            continue
        if reauth_account(account_id, auth_data):
            print(f"    ✅ Re-authed {email} successfully.")
            reauthed += 1
        else:
            print(f"    ❌ Re-auth failed for {email}.")
    print(f"  Done: {reauthed}/{len(reauth_needed)} re-authed.")
    return reauthed


def main():
    if "--loop" in sys.argv:
        while True:
            try:
                check_and_reauth()
            except Exception as e:
                print(f"  Error: {e}")
            time.sleep(CHECK_INTERVAL)
    else:
        check_and_reauth()


if __name__ == "__main__":
    main()

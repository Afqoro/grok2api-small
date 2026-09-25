#!/usr/bin/env python3
"""Bulk import accounts from grok2api original DB into grok2api-small.
- Decrypts refresh tokens in-memory (AES-256-GCM), never printed.
- Bounded concurrency (default 6), bounded timeout, 2 retries per account.
- Checkpoint file: skips accounts already imported on re-run.
"""
import base64, json, re, sqlite3, sys, time, threading, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SRC_DB = '/home/agentuser/apps/grok2api/data/backend.db'
SRC_CFG = '/home/agentuser/apps/grok2api/config.yaml'
DST = 'http://127.0.0.1:8792/api/admin/accounts/import'
CHECKPOINT = Path('/home/agentuser/apps/grok2api-small/data/import_checkpoint.json')
WORKERS = 6
TIMEOUT = 45
RETRIES = 2

def load_cipher_key():
    cfg = open(SRC_CFG).read()
    val = re.search(r'credentialEncryptionKey:\s*"?([^"\n]+)"?', cfg).group(1).strip()
    for cand in [val.encode(), base64.b64decode(val + '=' * (-len(val) % 4))]:
        if len(cand) in (16, 24, 32):
            return cand
    raise RuntimeError('no valid cipher key')

def main():
    ckey = load_cipher_key()
    src = sqlite3.connect(f'file:{SRC_DB}?mode=ro', uri=True)
    rows = src.execute(
        "SELECT c.account_id, c.encrypted_refresh, c.refresh_permanent "
        "FROM account_credentials c WHERE c.refresh_permanent=0 ORDER BY c.account_id"
    ).fetchall()
    # name/email from provider_accounts (build accounts)
    meta = {}
    for aid, email, uid in src.execute(
        "SELECT id, COALESCE(email,''), COALESCE(user_id,'') FROM provider_accounts"
    ):
        meta[aid] = (email, uid)
    src.close()

    done = set()
    if CHECKPOINT.exists():
        done = set(json.load(open(CHECKPOINT)))
    todo = [(aid, enc) for aid, enc, _ in rows if aid not in done]
    print(f'total eligible={len(rows)} already_done={len(done)} todo={len(todo)}', flush=True)

    lock = threading.Lock()
    ok_count = fail_count = skip_count = 0
    failures = []

    def import_one(item):
        nonlocal ok_count, fail_count, skip_count
        aid, enc = item
        try:
            raw = base64.b64decode(enc + '=' * (-len(enc) % 4))
            rt = AESGCM(ckey).decrypt(raw[:12], raw[12:], None).decode()
        except Exception as e:
            with lock:
                fail_count += 1
                failures.append({'account_id': aid, 'stage': 'decrypt', 'error': str(e)[:120]})
            return 'fail'
        email, uid = meta.get(aid, ('', ''))
        name = email or f'grok-{aid}'
        body = json.dumps({'refresh_token': rt, 'name': name}).encode()
        for attempt in range(RETRIES + 1):
            try:
                req = urllib.request.Request(DST, data=body, headers={'Content-Type': 'application/json'})
                resp = json.load(urllib.request.urlopen(req, timeout=TIMEOUT))
                if resp.get('status') == 'imported':
                    with lock:
                        ok_count += 1
                        done.add(aid)
                        if ok_count % 10 == 0:
                            json.dump(sorted(done), open(CHECKPOINT, 'w'))
                            print(f'progress ok={ok_count} fail={fail_count} ({ok_count + len(done) - ok_count} left)', flush=True)
                    return 'ok'
                else:
                    with lock:
                        skip_count += 1
                    return 'skip'
            except urllib.error.HTTPError as e:
                err_body = e.read()[:200].decode(errors='replace')
                if e.code in (400, 401) and 'invalid' in err_body.lower():
                    # permanent — do not retry
                    with lock:
                        fail_count += 1
                        failures.append({'account_id': aid, 'stage': 'http', 'code': e.code, 'error': err_body})
                    return 'fail'
                time.sleep(2 * (attempt + 1))
            except Exception:
                time.sleep(2 * (attempt + 1))
        with lock:
            fail_count += 1
            failures.append({'account_id': aid, 'stage': 'network', 'error': 'retries exhausted'})
        return 'fail'

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        list(pool.map(import_one, todo))

    json.dump(sorted(done), open(CHECKPOINT, 'w'))
    print(f'DONE ok={ok_count} fail={fail_count} skip={skip_count} total_done={len(done)}', flush=True)
    if failures:
        print('failure sample (first 20):', flush=True)
        for f in failures[:20]:
            print(f'  account_id={f["account_id"]} stage={f["stage"]} err={f.get("error","")[:80]}', flush=True)

if __name__ == '__main__':
    main()

"""Verify and reopen an actual QNX receipt in the shop-only server."""

from contextlib import closing, contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
from queue import Queue
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from shop_request import canonical

ROOT = Path(__file__).resolve().parent


@contextmanager
def shop_server(register, data_home):
    # Restrict the executable search path to the Python installation.
    env = {**os.environ, "PATH": str(Path(sys.executable).parent), "LOCALAPPDATA": str(data_home)}
    command = [sys.executable, str(ROOT / "live.py"), "--shop-only", "--shop-register", str(register)]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, text=True) as child:
        try:
            line = Queue(maxsize=1)
            Thread(target=lambda: line.put(child.stdout.readline().strip()), daemon=True).start()
            first = line.get(timeout=15)
            assert first.startswith("Shop: "), first
            yield first.split(maxsplit=1)[1]
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)


def request(url, data=None, status=200):
    headers = {}
    if data is not None:
        headers = {"Content-Type": "application/json", "Origin": f"http://{urlsplit(url).netloc}"}
        data = canonical(data).encode("ascii")
    try:
        response = urlopen(Request(url, data=data, headers=headers), timeout=5)
    except HTTPError as error:
        response = error
    with response:
        assert response.status == status, (url, response.status)
        return response.read()


def main():
    sample = json.loads((ROOT / "replay/qnx-road-scope-receipts.json").read_bytes())
    ticket = sample["requests"]["idle"]
    receipt = sample["receipts"]["idle"][0]
    issuer = canonical({"format": "repair-receipt-issuer/v1", "ed25519": sample["issuer"]["key"]})
    request_id = ticket["id"]
    moving_ticket = sample["requests"]["moving"]
    moving_id = moving_ticket["id"]
    moving_receipt = sample["receipts"]["moving"][0]
    with TemporaryDirectory(prefix="rr-shop-only-") as temporary:
        root = Path(temporary)
        register = root / "shop.sqlite3"
        data_home = root / "app-data"
        with shop_server(register, data_home) as shop:
            origin = "http://" + urlsplit(shop).netloc
            assert b"Shop intake" in request(shop)
            request(origin + "/driver.js", status=404)
            request(origin + "/review/example/state", status=404)
            request(origin + "/review/example/issuer", status=404)
            request(origin + "/review/example/decision", {"choice": "share"}, status=404)
            for control in (ticket, moving_ticket):
                created = json.loads(request(shop + "jobs", {"scope": control["scope"], "issuer": issuer,
                    "requestId": control["id"], "thresholdC": control["thresholdC"], "workOrder": "Archived QNX control"}, 201))
                assert created["request"] == control
                assert created["requestFingerprint"] == sha256(canonical(control).encode("ascii")).hexdigest()
            matched = json.loads(request(shop + "match", {"receipt": receipt, "request": ticket,
                                                         "fingerprint": sample["issuer"]["fingerprint"]}))
            assert matched["state"] == "ready" and matched["claim"]["idle"] == "observed"
            filed = json.loads(request(shop + "file", {"request": request_id, "receipt": receipt}))
            assert filed["job"]["acceptedAt"] and not filed["alreadyFiled"]
            request(shop + "file", {"request": moving_id, "receipt": moving_receipt})
        with shop_server(register, data_home) as shop:
            saved = json.loads(request(shop + "files/" + request_id))
            assert saved["receipt"] == receipt and saved["issuer"] == issuer
        assert sorted(path.name for path in root.iterdir()) == ["shop.sqlite3"]

        with shop_server(register, data_home) as shop:
            copied = root / "backup-copy.sqlite3"
            copied.write_bytes(request(shop + "backup"))
        for altered in (receipt.replace('"idle":"observed"', '"idle":"not_observed"'), "{", moving_receipt):
            assert altered != receipt
            with closing(sqlite3.connect(copied)) as db, db:
                db.execute("UPDATE intake_requests SET receipt = ? WHERE id = ?", (altered, request_id))
            with shop_server(copied, data_home) as shop:
                jobs = {job["request"]["id"]: job for job in json.loads(request(shop + "jobs"))["jobs"]}
                bad = jobs[request_id]
                assert bad["receiptInvalid"] and bad["claim"] is None and bad["acceptedAt"] is None
                assert jobs[moving_id]["claim"]["moving"] == "observed" and not jobs[moving_id]["receiptInvalid"]
                stored = json.loads(request(shop + "files/" + request_id))
                assert stored["job"] == bad and stored["receipt"] is None
                assert json.loads(request(shop + "files/" + moving_id))["receipt"] == moving_receipt
                request(shop + "work-order/" + request_id + "/evidence", status=400)
                request(shop + "match", {"receipt": receipt}, status=400)
                request(shop + "file", {"request": request_id, "receipt": receipt}, status=400)
            with closing(sqlite3.connect(copied)) as db:
                assert db.execute("SELECT receipt FROM intake_requests WHERE id = ?", (request_id,)).fetchone() == (altered,)
        with shop_server(register, data_home) as shop:
            saved = json.loads(request(shop + "files/" + request_id))
            assert saved["receipt"] == receipt and not saved["job"]["receiptInvalid"]
    print("Shop-only verified and reopened archived QNX receipts without driver endpoints or an issuer store.")
    print("Modified, malformed and wrong-request receipts in a backup copy were withheld while valid evidence stayed available.")


if __name__ == "__main__":
    main()

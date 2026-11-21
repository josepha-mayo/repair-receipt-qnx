"""Verify and reopen an actual QNX receipt in the shop-only server."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
from queue import Queue
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
            created = json.loads(request(shop + "jobs", {"scope": "idle", "issuer": issuer,
                "requestId": request_id, "thresholdC": ticket["thresholdC"], "workOrder": "Archived QNX control"}, 201))
            assert created["request"] == ticket
            matched = json.loads(request(shop + "match", {"receipt": receipt, "request": ticket,
                                                         "fingerprint": sample["issuer"]["fingerprint"]}))
            assert matched["state"] == "ready" and matched["claim"]["idle"] == "observed"
            filed = json.loads(request(shop + "file", {"request": request_id, "receipt": receipt}))
            assert filed["job"]["acceptedAt"] and not filed["alreadyFiled"]
        with shop_server(register, data_home) as shop:
            saved = json.loads(request(shop + "files/" + request_id))
            assert saved["receipt"] == receipt and saved["issuer"] == issuer
        assert sorted(path.name for path in root.iterdir()) == ["shop.sqlite3"]
    print("Shop-only server verified and reopened an archived QNX receipt without driver endpoints or an issuer store.")


if __name__ == "__main__":
    main()

"""Local browser workflow for a QNX-issued Repair Receipt."""

import argparse
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from math import ceil
from pathlib import Path
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
from tempfile import TemporaryDirectory
from threading import Event, Lock, Thread
import time
from urllib.parse import parse_qs, urlsplit
import webbrowser

from pack_shop import standalone
from run_qnx import MAX_RECORDING, ROOT, build_template, review_native
from shop_request import (
    CURRENT_RECIPE, DEFAULT_THRESHOLD_C, DEMO_SOURCE, PUBLISHED_SOURCE, STARTUP_RECIPE, UPLOADED_SOURCE,
    canonical, parse_request, request_fingerprint, verification_packet,
)

try:
    from issuer_store import Issuer, default_store, load_or_create_seed
    from shop_register import ReceiptConflict, RequestConflict, ShopRegister
except ModuleNotFoundError as error:
    if error.name != "cryptography":
        raise
    raise SystemExit("Install the local app dependencies with: python -m pip install -r requirements-live.txt") from None

CONSENT_SECONDS = 300
RECENT_RECEIPT_LIMIT = 16
RECENT_UPLOAD_LIMIT = 16
ACTIVE_STAGES = {"booting", "review", "finishing"}
SESSION_HEADER = "X-Repair-Session"
SAMPLES = {"trip-a", "trip-b", "moving", "gap", "scope-control"}
PUBLISHED_SAMPLES = {"kit-obd", "kit-july-26", "kit-july-27"}
ASSETS = {
    "/shop.js": ("shop.js", "text/javascript"),
    "/work-order-archive.js": ("work-order-archive.js", "text/javascript"),
    "/request.js": ("request.js", "text/javascript"),
    "/shared.css": ("shared.css", "text/css"),
    "/shop": ("shop.html", "text/html"),
}
DRIVER_ASSETS = {"/driver.js": ("driver.js", "text/javascript"), "/obd-csv.js": ("obd-csv.js", "text/javascript")}
REGISTER_ASSETS = {"/register.js": ("register.js", "text/javascript"), "/register.css": ("register.css", "text/css")}


def prepare_live_template(path):
    try:
        return build_template(path)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        print(f"QNX image preparation failed: {error}. Build log: {path / 'image-build.log'}", flush=True)
        raise


def startup_check(qemu_path):
    qemu = qemu_path or shutil.which("qemu-system-x86_64")
    if not qemu and os.name == "nt":
        qemu = r"C:\QNX\qemu\qemu-system-x86_64.exe"
    if not qemu or not Path(qemu).is_file():
        raise ValueError("Install QEMU for x86-64 and put it on PATH, or pass its executable with --qemu.")
    qemu = Path(qemu).resolve(strict=True)
    missing = [tool for tool in ("mkqnximage", "mkqnx6fsimg") if not shutil.which(tool)]
    if missing:
        raise ValueError(f"Missing SDK tools ({', '.join(missing)}). Load the QNX SDP 8.0 environment.")
    artifacts = [ROOT / "build" / name for name in ("repair-receipt", "secpol.bin")]
    if any(not path.is_file() or path.stat().st_size == 0 for path in artifacts):
        raise ValueError("Run build-qnx.cmd to compile the QNX app and security policy.")
    info = subprocess.run([qemu, "--version"], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=5)
    version = info.stdout.partition("\n")[0].strip()
    if info.returncode or not version.startswith("QEMU emulator version "):
        raise ValueError("The selected QEMU executable did not report a version. Check --qemu.")
    machines = subprocess.run([qemu, "-machine", "help"], stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=5)
    if machines.returncode or not re.search(r"^pc\s", machines.stdout, re.MULTILINE):
        raise ValueError("Choose QEMU for x86-64 with PC machine support.")
    return qemu, version


def receipt_rule(claim):
    return {"recipe": claim["recipe"], "scope": claim.get("scope", "both"),
            "thresholdC": claim.get("thresholdC", DEFAULT_THRESHOLD_C)}


class Review:
    def __init__(self, qemu, issuer, prepare):
        self.qemu = qemu
        self.issuer = issuer
        self.prepare = prepare
        self.template = prepare()
        self.lock = Lock()
        self.closed = False
        self.state = {"stage": "ready"}
        self.owner = None
        self.response = Event()
        self.decision = None
        self.deadline = None
        self.worker = None
        self.recent_receipts = OrderedDict()
        self.recent_uploads = OrderedDict()

    def owns_session(self, session):
        return session is not None and self.owner is not None and secrets.compare_digest(session, self.owner)

    def snapshot(self, session):
        with self.lock:
            remaining = None
            if self.state["stage"] == "review":
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    self._finish_decision("expired")
            if self.owns_session(session):
                state = dict(self.state)
                if remaining is not None and remaining > 0:
                    state["consentRemainingMs"] = ceil(remaining * 1000)
                return state
            occupied = self.state["stage"] in ACTIVE_STAGES
            saved = self.recent_receipts.get(session)
            if saved is not None:
                return {**saved, "otherReviewActive": occupied}
            return {"stage": "occupied" if occupied else "ready"}

    def template_status(self):
        template = self.template
        if not template.done():
            return "building"
        return "failed" if template.exception() else "ready"

    def retry_preparation(self):
        with self.lock:
            if self.closed or self.state["stage"] in ACTIVE_STAGES or self.template_status() != "failed":
                return False
            self.template = self.prepare()
            self.owner = None
            self.state = {"stage": "ready"}
            return True

    def start(self, session, recording, request, *, bench=None, source=None, request_checked=False):
        with self.lock:
            if self.closed or self.state["stage"] in ACTIVE_STAGES or self.template_status() == "failed":
                return False
            self.recent_receipts.pop(session, None)
            if self.state["stage"] == "shared" and not self.owns_session(session):
                # Recovery only needs the approved export and its display fields.
                fields = ("stage", "job", "claim", "issuer", "receipt", "packet")
                self.recent_receipts[self.owner] = {key: self.state[key] for key in fields if key in self.state}
                if len(self.recent_receipts) > RECENT_RECEIPT_LIMIT:
                    self.recent_receipts.popitem(last=False)
            job = secrets.token_urlsafe(12)
            self.owner = session
            self.state = {"stage": "booting", "job": job, "bench": bench is not None}
            if request_checked:
                self.state["requestFingerprintMatched"] = True
            self.response = Event()
            self.decision = None
            self.deadline = None
            self.worker = Thread(target=self.run, args=(self.template, recording, request, bench, source))
            self.worker.start()
        return True

    def decide(self, session, job, choice):
        with self.lock:
            if not self.owns_session(session) or self.state["stage"] != "review" or self.state["job"] != job:
                return False
            timely = time.monotonic() < self.deadline
            self._finish_decision(choice if timely else "expired")
            return timely

    def _finish_decision(self, decision):
        """Commit a decision with the review lock held."""
        self.decision = decision
        self.state["stage"] = "finishing"
        self._clear_private_notes()
        if decision == "expired":
            for field in ("claim", "coverage", "issuer"):
                self.state.pop(field, None)
        self.response.set()

    def _clear_private_notes(self):
        for field in ("reusedRecording", "previousRecordingRule", "startupExcludedMs", "coverageDetail"):
            self.state.pop(field, None)

    def _note_upload(self, import_review, claim):
        digest, request_id = import_review
        key = (self.owner, digest)
        first_request, prior_rule = self.recent_uploads.setdefault(key, (request_id, None))
        self.recent_uploads.move_to_end(key)
        if len(self.recent_uploads) > RECENT_UPLOAD_LIMIT:
            self.recent_uploads.popitem(last=False)
        if first_request != request_id:
            self.state["reusedRecording"] = True
        if prior_rule and prior_rule != receipt_rule(claim):
            self.state["previousRecordingRule"] = prior_rule

    def wait_for_decision(self, preview, issuer, guest_closed, coverage=None, import_review=None, *,
                          startup_excluded_ms=None, coverage_detail=None):
        if not secrets.compare_digest(self.issuer.public_hex.encode("ascii"), issuer):
            raise RuntimeError("The guest presented a key different from the enrolled issuer.")
        with self.lock:
            self.deadline = time.monotonic() + CONSENT_SECONDS
            claim = json.loads(preview)
            self.state.update(stage="review", claim=claim, issuer=issuer.decode("ascii"))
            if coverage:
                self.state["coverage"] = coverage
            if coverage_detail:
                self.state["coverageDetail"] = coverage_detail
            if startup_excluded_ms is not None:
                self.state["startupExcludedMs"] = startup_excluded_ms
            if import_review is not None:
                self._note_upload(import_review, claim)
        self.response.wait(timeout=max(0, self.deadline - time.monotonic()))
        with self.lock:
            if guest_closed.is_set():
                raise RuntimeError("QNX disconnected while waiting for the driver's decision.")
            self._finish_decision(self.decision or "expired")
            return self.decision == "share"

    def run(self, template, recording, request, bench, source):
        guest_closed = Event()
        response = self.response
        coverage = {}
        coverage_detail = {}
        startup_excluded_ms = None

        def record_startup_window(duration):
            nonlocal startup_excluded_ms
            startup_excluded_ms = duration

        def disconnect():
            guest_closed.set()
            response.set()

        image = None
        issued_rule = None
        try:
            image = template.result()
            import_review = None
            if source == UPLOADED_SOURCE:
                import_review = (sha256(recording).digest(), request["id"] if request is not None else None)
            with TemporaryDirectory(prefix="repair-receipt-") as directory:
                receipt = review_native(Path(directory) / "guest", self.qemu, recording,
                                        lambda preview, issuer: self.wait_for_decision(
                                            preview, issuer, guest_closed, coverage, import_review,
                                            startup_excluded_ms=startup_excluded_ms, coverage_detail=coverage_detail),
                                        self.issuer.seed, request, bench, image=image, on_disconnect=disconnect,
                                        source=source, on_coverage=coverage.update, on_startup_window=record_startup_window,
                                        on_coverage_detail=coverage_detail.update)
                result = {"stage": "expired" if self.decision == "expired" else "declined"}
                if receipt is not None:
                    self.issuer.verify_receipt(receipt)
                    result = {"stage": "shared", "receipt": receipt.decode("ascii")}
                    if import_review is not None:
                        issued_rule = receipt_rule(json.loads(receipt)["claim"])
                    if request is not None:
                        result["packet"] = verification_packet(request, result["receipt"], self.issuer.fingerprint)
        except ValueError:
            message = ("QNX could not complete the simulated OBD capture." if bench else
                       "QNX rejected this recording. Check the CSV columns and timestamps.")
            result = {"stage": "error", "message": message}
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            print(f"Repair Receipt guest error: {error}", flush=True)
            result = {"stage": "error", "message": "QNX could not complete this review. Start a fresh review and check the local console."}
        if image is None:
            result = {"stage": "error", "message": "QNX preparation failed. Retry preparation from the recording panel."}
        with self.lock:
            self._clear_private_notes()
            if issued_rule is not None:
                key = (self.owner, import_review[0])
                first_request, _ = self.recent_uploads[key]
                self.recent_uploads[key] = (first_request, issued_rule)
            self.state.update(result)

    def close(self):
        with self.lock:
            self.closed = True
            if self.decision is None:
                self.decision = "decline"
            self.response.set()
            worker = self.worker
        if worker:
            worker.join()


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_args):
        pass

    def send(self, status, body, mime, filename=None):
        self.send_body_headers(status, mime, len(body), filename)
        self.wfile.write(body)

    def send_body_headers(self, status, mime, size, filename=None):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; script-src 'self'; style-src 'self'; "
                         "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        if filename is not None:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()

    def json(self, status, body):
        self.send(status, json.dumps(body).encode(), "application/json")

    def driver_session(self):
        values = self.headers.get_all(SESSION_HEADER, [])
        return values[0] if len(values) == 1 and re.fullmatch(r"[a-f0-9]{32}", values[0]) else None

    def do_GET(self):
        if self.headers.get("Host") != self.server.host:
            self.json(400, {"message": "Invalid local host."})
            return
        if self.path == "/verify-receipt.html":
            self.send(200, standalone(), "application/octet-stream")
            return
        asset = self.server.assets.get(self.path)
        driver = self.server.driver
        shop_path = self.server.shop_path
        if asset:
            name, mime = asset
            body = (ROOT / "web" / name).read_bytes()
            if self.server.practice and name in ("driver.html", "register.html"):
                body = body.replace(b'id="practice-note" hidden', b'id="practice-note"', 1)
            self.send(200, body, mime + "; charset=utf-8")
        elif driver and self.path == driver + "state":
            body = self.server.review.snapshot(self.driver_session())
            body["template"] = self.server.review.template_status()
            self.json(200, body)
        elif driver and self.path == driver + "issuer":
            self.json(200, self.server.review.issuer.public_profile())
        elif shop_path and self.path.startswith(shop_path):
            self.shop_get()
        else:
            self.json(404, {"message": "Page unavailable."})

    def shop_get(self):
        try:
            path = urlsplit(self.path.removeprefix(self.server.shop_path))
            if path.path == "jobs":
                query = parse_qs(path.query, keep_blank_values=True)
                if not query:
                    before = None
                elif set(query) == {"before"} and len(query["before"]) == 1 and re.fullmatch(
                    r"[1-9][0-9]{0,17}", query["before"][0]
                ):
                    before = int(query["before"][0])
                else:
                    raise ValueError("Invalid page cursor.")
                self.json(200, self.server.register.list(before))
            elif not path.query and re.fullmatch(r"files/[a-f0-9]{32}", path.path):
                row = self.server.register.fetch(path.path[6:])
                job = self.server.register.job(row)
                self.json(200, {
                    "job": job,
                    "receipt": None if job["receiptInvalid"] else row["receipt"],
                    "issuer": canonical({"format": "repair-receipt-issuer/v1", "ed25519": row["issuer"].hex()})
                              if job["fingerprint"] else None,
                })
            elif not path.query and re.fullmatch(r"work-order/[a-f0-9]{32}", path.path):
                self.json(200, self.server.register.work_order_findings(path.path.split("/")[1]))
            elif not path.query and re.fullmatch(r"work-order/[a-f0-9]{32}/evidence", path.path):
                original, archive = self.server.register.work_order_archive(path.path.split("/")[1])
                self.send(200, archive, "application/zip", f"repair-work-order-{original}.zip")
            elif path.path == "backup" and not path.query:
                self.shop_backup()
            else:
                self.json(404, {"message": "Page unavailable."})
        except ValueError as error:
            self.json(400, {"message": str(error)})
        except KeyError as error:
            self.json(404, {"message": error.args[0]})
        except sqlite3.Error:
            self.json(503, {"message": "The local shop register is unavailable. Try again."})

    def shop_backup(self):
        with ExitStack() as files:
            try:
                temporary = files.enter_context(TemporaryDirectory(prefix="repair-receipt-backup-"))
                snapshot = Path(temporary) / "shop.sqlite3"
                self.server.register.backup(snapshot)
                stream = files.enter_context(snapshot.open("rb"))
                size = os.fstat(stream.fileno()).st_size
            except (OSError, sqlite3.Error):
                self.send(503, b"Could not prepare a register backup. Check the local register and try again.",
                          "text/plain; charset=utf-8")
                return
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            try:
                self.send_body_headers(200, "application/octet-stream", size, f"repair-receipt-shop-{stamp}.sqlite3")
                shutil.copyfileobj(stream, self.wfile)
            except OSError:
                self.close_connection = True

    def shop_post(self, body):
        if self.headers.get_content_type() != "application/json":
            self.json(415, {"message": "Choose a request or signed receipt from the shop page."})
            return
        action = self.path.removeprefix(self.server.shop_path)
        try:
            value = json.loads(body)
            fields = value.keys() if isinstance(value, dict) else set()
            if action == "jobs" and {"scope", "issuer"} <= fields <= {
                "scope", "issuer", "workOrder", "thresholdC", "recipe", "requestId",
            }:
                self.json(201, self.server.register.create(value["scope"], value["issuer"], value.get("workOrder"),
                                                          value.get("thresholdC"), recipe=value.get("recipe", CURRENT_RECIPE),
                                                          request_id=value.get("requestId")))
            elif action == "lookup" and {"workOrder"} <= fields <= {"workOrder", "before"}:
                self.json(200, self.server.register.lookup(value["workOrder"], value.get("before")))
            elif action == "follow-up" and isinstance(value, dict) and set(value) == {"request"}:
                self.json(200, self.server.register.follow_up(value["request"]))
            elif action == "recheck" and fields == {"request"}:
                self.json(200, self.server.register.repeat(value["request"], recheck=True))
            elif action == "replace-review" and fields == {"request"}:
                self.json(200, self.server.register.replace_review(value["request"]))
            elif action == "file" and isinstance(value, dict) and set(value) == {"request", "receipt"}:
                self.json(200, self.server.register.attach(value["request"], value["receipt"]))
            elif action == "match" and fields in ({"receipt"}, {"receipt", "request", "fingerprint"}):
                packet = value if "request" in value else None
                self.json(200, self.server.register.match(value["receipt"], packet=packet))
            else:
                self.json(400, {"message": "Invalid shop register action."})
        except (ReceiptConflict, RequestConflict) as error:
            self.json(409, {"message": str(error)})
        except KeyError as error:
            self.json(404, {"message": error.args[0]})
        except json.JSONDecodeError:
            self.json(400, {"message": "Choose a valid JSON request, key or receipt file."})
        except ValueError as error:
            self.json(400, {"message": str(error)})
        except sqlite3.Error:
            self.json(503, {"message": "The local shop register is unavailable. Try again."})

    def do_POST(self):
        if (self.headers.get("Host") != self.server.host or
                self.headers.get("Origin") != "http://" + self.server.host):
            self.json(403, {"message": "Open the local app to continue."})
            return
        shop_path, driver = self.server.shop_path, self.server.driver
        shop_action = shop_path and self.path.startswith(shop_path)
        path = self.path.removeprefix(driver) if driver and self.path.startswith(driver) else None
        if not shop_action and path is None:
            self.json(404, {"message": "Action unavailable."})
            return
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length") or []) != 1:
            self.json(400, {"message": "Invalid request length."})
            return
        try:
            size = int(self.headers["Content-Length"])
            limit = 2048 if shop_action else MAX_RECORDING
            if not 0 < size <= limit:
                message = "Choose a supported request or receipt file." if shop_action else "Choose a recording under 4 MiB."
                self.json(413, {"message": message})
                return
            body = self.rfile.read(size)
            if len(body) != size:
                raise ValueError("Incomplete body")
        except (ValueError, socket.timeout):
            self.json(400, {"message": "The request could not be read."})
            return
        if shop_action:
            self.shop_post(body)
            return
        session = self.driver_session()
        if path in {"import", "sample", "decision", "prepare"} and session is None:
            self.json(403, {"message": "Open the driver page to start a private review."})
            return
        request = None
        request_headers = self.headers.get_all("X-Repair-Request")
        fingerprints = self.headers.get_all("X-Repair-Request-SHA256", [])
        if path in {"import", "sample"} and request_headers:
            try:
                if len(request_headers) != 1:
                    raise ValueError("Duplicate request header.")
                request = parse_request(request_headers[0])
            except ValueError:
                self.json(400, {"message": "Choose a request file created by Repair Receipt."})
                return
        if path in {"import", "sample"} and fingerprints:
            if (request is None or len(fingerprints) != 1 or not re.fullmatch(r"[a-f0-9]{64}", fingerprints[0]) or
                    not secrets.compare_digest(fingerprints[0], request_fingerprint(request))):
                self.json(400, {"message": "The request file differs from the fingerprint you entered."})
                return
        request_checked = bool(fingerprints)
        if path == "import" and self.headers.get_content_type() == "application/octet-stream":
            ok = self.server.review.start(session, body, request, source=UPLOADED_SOURCE, request_checked=request_checked)
        elif path == "sample" and size <= 32:
            name = body.decode("ascii", errors="replace")
            if name == "obd-bench":
                if request is None:
                    self.json(400, {"message": "Load a shop request before starting the OBD bench."})
                    return
                if request["recipe"] == STARTUP_RECIPE:
                    self.json(400, {"message": "Choose a recording for this request’s startup allowance."})
                    return
                ok = self.server.review.start(session, None, request, bench="normal", request_checked=request_checked)
            elif name not in SAMPLES and name not in PUBLISHED_SAMPLES:
                self.json(400, {"message": "Unknown sample recording."})
                return
            else:
                source = PUBLISHED_SOURCE if name in PUBLISHED_SAMPLES else DEMO_SOURCE
                try:
                    recording = (ROOT / "fixtures" / f"{name}.csv").read_bytes()
                except OSError:
                    self.json(503, {"message": "The sample recording is unavailable. Check the source download."})
                    return
                ok = self.server.review.start(session, recording, request, source=source, request_checked=request_checked)
        elif path == "decision" and size <= 256:
            try:
                value = json.loads(body)
                job, choice = value["job"], value["choice"]
                if not isinstance(job, str) or choice not in ("share", "decline"):
                    raise ValueError("Invalid decision")
            except (ValueError, KeyError, TypeError):
                self.json(400, {"message": "Invalid decision."})
                return
            ok = self.server.review.decide(session, job, choice)
        elif path == "prepare" and body == b"{}" and self.headers.get_content_type() == "application/json":
            ok = self.server.review.retry_preparation()
        else:
            self.json(404, {"message": "Action unavailable."})
            return
        self.json(202 if ok else 409, {} if ok else {"message": "Refresh the page and check the current review."})


def serve(args, qemu, issuer, register):
    with ThreadingHTTPServer(("127.0.0.1", args.port), Handler) as server, ExitStack() as resources:
        server.host = f"127.0.0.1:{server.server_port}"
        server.practice = args.practice
        server.assets = ASSETS.copy()
        server.driver = server.shop_path = None
        driver_url = shop_url = None
        if issuer is not None:
            server.driver = f"/review/{secrets.token_urlsafe(24)}/"
            server.assets.update(DRIVER_ASSETS)
            server.assets[server.driver] = ("driver.html", "text/html")
            workspace = resources.enter_context(TemporaryDirectory(prefix="repair-receipt-template-"))
            builds = resources.enter_context(ThreadPoolExecutor(max_workers=1))

            def prepare():
                return builds.submit(prepare_live_template, Path(workspace) / secrets.token_hex(8))

            server.review = Review(qemu, issuer, prepare)
            resources.callback(server.review.close)
            driver_url = f"http://{server.host}{server.driver}"
        server.register = register
        if register is not None:
            server.shop_path = f"/intake/{secrets.token_urlsafe(24)}/"
            server.assets.update(REGISTER_ASSETS)
            server.assets[server.shop_path] = ("register.html", "text/html")
            shop_url = f"http://{server.host}{server.shop_path}"
        if args.practice:
            print("Practice session. This session uses a temporary driver key and shop register.", flush=True)
        if driver_url:
            print(f"Driver: {driver_url}", flush=True)
        if shop_url:
            print(f"Shop:   {shop_url}", flush=True)
        print(f"Offline verifier: http://{server.host}/shop", flush=True)
        if args.open:
            webbrowser.open(driver_url or shop_url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu_path", nargs="?", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--qemu", type=Path, help="path to qemu-system-x86_64")
    setup = parser.add_mutually_exclusive_group()
    setup.add_argument("--check", action="store_true", help="check available SDK tools, QEMU and the build")
    setup.add_argument("--self-test", action="store_true",
                       help="boot QNX and verify scoped signing, consent and the native export grant")
    setup.add_argument("--policy-lab", action="store_true",
                       help="run the native channel-grant and consent trials and print their JSON results")
    setup.add_argument("--road-lab", action="store_true",
                       help="compare four native QNX receipts from the two bundled KIT drives")
    setup.add_argument("--practice", action="store_true", help="run with a temporary driver key and shop register")
    setup.add_argument("--shop-only", action="store_true", help="run the shop register without QNX or a driver key")
    setup.add_argument("--driver-only", action="store_true", help="run the QNX review without a shop register")
    parser.add_argument("--policy-transcript", type=Path, help="save a new Markdown transcript from --policy-lab")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--open", action="store_true", help="open the active driver or shop page in your browser")
    parser.add_argument("--shop-register", type=Path, help="path for the local SQLite shop register")
    issuer_options = parser.add_mutually_exclusive_group()
    issuer_options.add_argument("--issuer-store", type=Path, help="path for the Windows-protected issuer")
    issuer_options.add_argument("--ephemeral-issuer", action="store_true", help="use a temporary issuer for this launch")
    args = parser.parse_args()
    if args.qemu and args.qemu_path:
        parser.error("Supply one QEMU executable path.")
    if args.policy_transcript is not None and not args.policy_lab:
        parser.error("--policy-transcript requires --policy-lab.")
    if args.practice and (args.issuer_store or args.ephemeral_issuer or args.shop_register):
        parser.error("--practice already uses a temporary issuer and shop register.")
    if args.shop_only and (args.qemu or args.qemu_path or args.issuer_store or args.ephemeral_issuer):
        parser.error("--shop-only does not use QEMU or an issuer store.")
    if args.driver_only and args.shop_register:
        parser.error("--driver-only does not use a shop register.")
    try:
        with ExitStack() as resources:
            qemu = issuer = register = None
            if not args.shop_only:
                qemu, version = startup_check(args.qemu or args.qemu_path)
                if args.check:
                    print(f"Ready to start Repair Receipt. {version}\nQEMU: {qemu}")
                    return
                if (args.self_test or args.policy_lab) and not shutil.which("secpolcompile"):
                    raise ValueError("Missing SDK tool (secpolcompile). Load the QNX SDP 8.0 environment.")
                if args.road_lab:
                    from verify_requests import BUNDLED_ROAD_PAIR, verify_road_pair

                    print(json.dumps(verify_road_pair(qemu, BUNDLED_ROAD_PAIR), indent=2))
                    return
                if args.policy_lab:
                    from verify_policy import verify

                    print(json.dumps(verify(qemu, args.policy_transcript), indent=2))
                    return
                if args.self_test:
                    from verify_requests import verify

                    print(f"Running Repair Receipt's QNX self-test. {version}", flush=True)
                    verify(qemu, check_export_grant=True)
                    print("Passed. Four signatures verified, the idle receipts matched, the moving receipts differed, "
                          "and declining produced no receipt. Removing the QNX export grant blocked an approved receipt.")
                    return
                ephemeral = args.practice or args.ephemeral_issuer
                seed = secrets.token_bytes(32) if ephemeral else load_or_create_seed(
                    (args.issuer_store or default_store()).resolve()
                )
                issuer = Issuer(seed, durable=not ephemeral)
            if not args.driver_only:
                if args.practice:
                    directory = resources.enter_context(TemporaryDirectory(prefix="repair-receipt-practice-"))
                    register_path = Path(directory) / "shop.sqlite3"
                else:
                    app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share"))
                    register_path = args.shop_register or (
                        args.issuer_store.with_name("shop.sqlite3")
                        if args.issuer_store else app_data / "RepairReceipt" / "shop.sqlite3"
                    )
                register = ShopRegister(register_path.resolve())
            serve(args, qemu, issuer, register)
    except (OSError, ValueError, RuntimeError, KeyError, sqlite3.Error, subprocess.SubprocessError) as error:
        parser.exit(1, f"Repair Receipt could not start: {error}\n")


if __name__ == "__main__":
    main()

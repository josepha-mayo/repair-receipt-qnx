"""Exercise the shop register's concurrency and pinned-issuer controls."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Barrier
from unittest.mock import patch
from zipfile import ZipFile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shop_register import INVALID_SAVED_RECEIPT, PAGE_SIZE, ReceiptConflict, RequestConflict, ShopRegister, check_receipt, read_receipt
from shop_request import (
    CURRENT_RECIPE, DEFAULT_THRESHOLD_C, PUBLISHED_SOURCE, RECIPE, canonical, guest_bytes,
    parse_request, verification_packet,
)
from verify_requests import BUNDLED_ROAD_PAIR, load_road_pair


def pin(key):
    return canonical({"format": "repair-receipt-issuer/v1",
                      "ed25519": key.public_key().public_bytes_raw().hex()})


def verify_archived_road_pair():
    replay = Path(__file__).resolve().parent / "replay"
    evidence = json.loads((replay / "qnx-road-scope-receipts.json").read_text(encoding="utf-8"))
    proof = json.loads((replay / "qnx-road-scope-proof.json").read_text(encoding="utf-8"))
    for (name, recording, digest), archived in zip(load_road_pair(BUNDLED_ROAD_PAIR), proof["recordings"], strict=True):
        assert (name, len(recording), digest) == (archived["recording"], archived["normalized_bytes"], archived["normalized_sha256"])
    key = bytes.fromhex(evidence["issuer"]["key"])
    assert sha256(key).hexdigest() == evidence["issuer"]["fingerprint"]
    for scope, findings in (("idle", ["observed", "observed"]), ("moving", ["observed", "insufficient_evidence"])):
        request = parse_request(canonical(evidence["requests"][scope]))
        assert request["scope"] == scope and request["thresholdC"] == proof["test_threshold_c"]
        receipts = evidence["receipts"][scope]
        claims = [check_receipt(text, read_receipt(text), request, key) for text in receipts]
        assert [claim[scope] for claim in claims] == findings
        assert [recording[scope] for recording in proof["recordings"]] == findings
        assert all(claim["source"] == PUBLISHED_SOURCE for claim in claims)
        assert (receipts[0] == receipts[1]) == (scope == "idle")
    idle = evidence["receipts"]["idle"][0].encode("ascii")
    assert len(idle) == proof["idle_receipt_bytes"]
    assert sha256(idle).hexdigest() == proof["idle_receipt_sha256"]
    disclosure = json.loads((replay / "qnx-road-disclosure.json").read_bytes())
    packet = verification_packet(evidence["requests"]["idle"], idle.decode("ascii"), evidence["issuer"]["fingerprint"])
    packet_bytes = canonical(packet).encode("ascii")
    measured = disclosure["shared_idle_reply"]
    assert measured["signed_receipt_bytes"] == len(idle)
    assert measured["signed_claim_fields"] == sorted(json.loads(idle)["claim"])
    assert measured["verification_packet_bytes"] == len(packet_bytes)
    assert measured["verification_packet_sha256"] == sha256(packet_bytes).hexdigest()
    for record, native in zip(disclosure["recordings"], proof["recordings"], strict=True):
        assert record["name"] == native["recording"]
        assert record["normalized_qnx_input"]["bytes"] == native["normalized_bytes"]
        assert record["normalized_qnx_input"]["sha256"] == native["normalized_sha256"]
    print("Verified the bundled road inputs, archived signatures, request bindings and measured verification packet.")


def sign(request, result, key):
    claim = {"recipe": request["recipe"]}
    if "thresholdC" in request:
        claim["thresholdC"] = request["thresholdC"]
    claim.update(request=request["id"], scope=request["scope"])
    claim.update(result if isinstance(result, dict) else {"idle": result})
    signature = key.sign(b"Repair Receipt v2\n" + canonical(claim).encode("ascii"))
    return canonical({"format": "repair-receipt/v2", "claim": claim, "signature": signature.hex()})


def verify_create_retry():
    owner = Ed25519PrivateKey.generate()
    issuer = pin(owner)
    request_id = "31" * 16
    details = ("idle", issuer, "Retry work order", 106)
    with TemporaryDirectory(prefix="rr-create-retry-") as scratch:
        path = Path(scratch) / "register.sqlite3"
        register = ShopRegister(path)
        start = Barrier(8)

        def race(_):
            start.wait()
            return register.create(*details, request_id=request_id)

        with ThreadPoolExecutor(max_workers=start.parties) as pool:
            replies = list(pool.map(race, range(start.parties)))
        job = replies[0]
        assert job["request"]["id"] == request_id
        assert replies == [job] * start.parties
        register = ShopRegister(path)
        assert register.list()["jobs"] == [job]
        for changed in (
            ("moving", *details[1:]),
            ("idle", pin(Ed25519PrivateKey.generate()), *details[2:]),
            (*details[:2], "Other work order", 106),
            (*details[:3], 107),
        ):
            try:
                register.create(*changed, request_id=request_id)
            except RequestConflict:
                pass
            else:
                raise AssertionError("A retry reused the ID for different request details.")
        receipt = sign(job["request"], "observed", owner)
        register.attach(request_id, receipt)
        returned = register.create(*details, request_id=request_id)
        assert returned["acceptedAt"] and returned["request"] == job["request"]
        assert register.fetch(request_id)["receipt"] == receipt
        second = register.create(*details, request_id="32" * 16)
        assert second["request"]["id"] != request_id
        assert len(register.lookup(details[2])["jobs"]) == 2
    print("Verified concurrent creation retries, mismatched details, and original receipt preservation.")


with TemporaryDirectory(prefix="rr-register-concurrency-") as scratch:
    path = Path(scratch) / "register.sqlite3"
    owner = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    legacy = {"format": "repair-receipt-request/v1", "recipe": RECIPE, "scope": "idle", "id": "a" * 32}
    open_legacy = {**legacy, "id": "b" * 32}
    legacy_receipt = sign(legacy, "observed", owner)
    with sqlite3.connect(path) as database:
        database.execute("""CREATE TABLE intake_requests (
            number INTEGER PRIMARY KEY, id TEXT NOT NULL UNIQUE, scope TEXT NOT NULL,
            issuer BLOB NOT NULL, created_at TEXT NOT NULL, receipt TEXT, accepted_at TEXT
        )""")
        database.execute("""INSERT INTO intake_requests(id, scope, issuer, created_at, receipt, accepted_at)
            VALUES (?, 'idle', ?, ?, ?, ?)""", (
            legacy["id"], owner.public_key().public_bytes_raw(),
            "2026-11-18T14:00:00+00:00", legacy_receipt, "2026-11-18T14:01:00+00:00",
        ))
        database.execute("INSERT INTO intake_requests(id, scope, issuer, created_at) VALUES (?, 'idle', ?, ?)",
                         (open_legacy["id"], owner.public_key().public_bytes_raw(), "2026-11-18T15:00:00+00:00"))
    database.close()
    register = ShopRegister(path)
    assert [item["request"] for item in register.list()["jobs"]] == [open_legacy, legacy]
    assert register.list()["jobs"][0]["workOrder"] is None
    assert register.fetch(legacy["id"])["receipt"] == legacy_receipt
    assert register.attach(legacy["id"], legacy_receipt)["alreadyFiled"]
    assert not register.attach(open_legacy["id"], sign(open_legacy, "observed", owner))["alreadyFiled"]
    request = register.create("idle", pin(owner))["request"]
    assert request["recipe"] == CURRENT_RECIPE
    for invalid_threshold in (True, 105.0, -41, 201):
        try:
            register.create("idle", pin(owner), threshold=invalid_threshold)
        except ValueError as error:
            assert "whole temperature" in str(error)
        else:
            raise AssertionError("An invalid diagnostic threshold entered the register.")
    try:
        register.attach(request["id"], sign({**request, "recipe": RECIPE}, "observed", owner))
    except ValueError as error:
        assert "does not match the selected request" in str(error)
    else:
        raise AssertionError("The sample-count rule replaced the signed duration rule.")
    try:
        register.attach(request["id"], sign(request, "observed", other))
    except ValueError as error:
        assert "does not match the issuer" in str(error)
    else:
        raise AssertionError("An independently signed receipt replaced the pinned issuer.")
    assert register.fetch(request["id"])["receipt"] is None

    contestants = [
        sign(request, "observed" if index % 2 else "insufficient_evidence", owner)
        for index in range(12)
    ]
    start = Barrier(len(contestants))

    def race(receipt):
        start.wait()
        try:
            response = register.attach(request["id"], receipt)
            return "same" if response["alreadyFiled"] else "filed"
        except ReceiptConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=len(contestants)) as pool:
        outcomes = list(pool.map(race, contestants))
    assert outcomes.count("filed") == 1
    assert outcomes.count("same") == 5
    assert outcomes.count("conflict") == 6
    winner = contestants[outcomes.index("filed")]
    reopened = ShopRegister(path)
    assert reopened.fetch(request["id"])["receipt"] == winner
    assert json.loads(winner)["claim"] == reopened.list()["jobs"][0]["claim"]

    for _ in range(PAGE_SIZE + 2):
        register.create("idle", pin(owner))
    page = register.list()
    after = register.list(page["before"])
    ids = [job["request"]["id"] for part in [page, after] for job in part["jobs"]]
    assert len(ids) == len(set(ids)) == PAGE_SIZE + 5
    assert after["before"] is None

    local_reference = "WO-1846 / Bay 2"
    threshold = DEFAULT_THRESHOLD_C + 3
    incomplete = register.create("both", pin(owner), "  " + local_reference + "  ", threshold)["request"]
    assert parse_request(canonical(incomplete)) == incomplete
    assert incomplete["format"] == "repair-receipt-request/v2" and incomplete["thresholdC"] == threshold
    assert guest_bytes(incomplete)[-2:] == bytes((3, threshold + 40))
    for unsuitable in (incomplete["id"], legacy["id"]):
        try:
            register.follow_up(unsuitable)
        except ValueError as error:
            assert "filed receipt with insufficient evidence" in str(error)
        else:
            raise AssertionError("A resolved or open request created a follow-up.")
    original = sign(incomplete, {"idle": "observed", "moving": "insufficient_evidence"}, owner)
    matched = register.match(original)
    assert matched["state"] == "ready" and matched["job"]["workOrder"] == local_reference
    assert matched["job"]["acceptedAt"] is None and register.fetch(incomplete["id"])["receipt"] is None
    assert local_reference not in original and "workOrder" not in incomplete
    packet = verification_packet(incomplete, original, matched["job"]["fingerprint"])
    assert register.match(packet["receipt"], packet=packet) == matched
    for changed, message in (
        ({"request": {**incomplete, "thresholdC": threshold + 1}}, "does not match the original shop request"),
        ({"fingerprint": "0" * 64}, "does not match the enrolled issuer"),
    ):
        try:
            register.match(original, packet={**packet, **changed})
        except ValueError as error:
            assert message in str(error)
        else:
            raise AssertionError("A changed packet binding matched the work order.")
    try:
        register.match(sign({**incomplete, "thresholdC": threshold + 1},
                            {"idle": "observed", "moving": "insufficient_evidence"}, owner))
    except ValueError as error:
        assert "does not match the selected request" in str(error)
    else:
        raise AssertionError("A valid signature replaced the requested threshold.")
    try:
        register.match(sign(incomplete, {"idle": "observed", "moving": "insufficient_evidence"}, other))
    except ValueError as error:
        assert "does not match the issuer" in str(error)
    else:
        raise AssertionError("An independently signed receipt located the work order.")
    register.attach(incomplete["id"], original)
    assert register.match(original)["state"] == "alreadyFiled"
    altered = sign(incomplete, {"idle": "not_observed", "moving": "insufficient_evidence"}, owner)
    assert register.match(altered)["state"] == "conflict"
    start = Barrier(12)

    def repeat(_):
        start.wait()
        return register.follow_up(incomplete["id"])

    with ThreadPoolExecutor(max_workers=12) as pool:
        children = list(pool.map(repeat, range(12)))
    child = children[0]
    assert all(result == child for result in children)
    assert child["repeats"] == incomplete["id"]
    assert child["request"]["scope"] == "moving"
    assert child["request"]["recipe"] == incomplete["recipe"]
    assert child["workOrder"] == local_reference
    assert set(child["request"]) == {"id", "format", "scope", "recipe", "thresholdC"}
    assert child["request"]["thresholdC"] == threshold
    reopened = ShopRegister(path)
    parent_row = reopened.fetch(incomplete["id"])
    assert parent_row["follow_up"] == child["request"]["id"]
    assert parent_row["receipt"] == original
    assert parent_row["issuer"] == reopened.fetch(child["request"]["id"])["issuer"]
    child_id = child["request"]["id"]
    order = reopened.work_order_findings(child_id)
    assert order["workOrder"] == local_reference and order["originalRequest"] == incomplete["id"]
    assert order["pending"] == {"request": child_id, "scope": "moving", "purpose": "follow-up"}
    idle, moving = order["contexts"]
    assert idle["evidence"]["request"] == incomplete["id"] and idle["evidence"]["finding"] == "observed"
    assert moving["evidence"]["finding"] == "insufficient_evidence" and moving["pendingRequest"] == child_id
    original_id, first_archive = reopened.work_order_archive(child_id)
    assert original_id == incomplete["id"]
    with ZipFile(BytesIO(first_archive)) as bundle:
        assert bundle.namelist() == [f"repair-verification-{original_id}.json"]
    same_reference = reopened.create("idle", pin(owner), local_reference)
    separate_id = same_reference["request"]["id"]
    separate = reopened.work_order_findings(separate_id)
    assert separate["contexts"][0]["evidence"] is None
    assert separate["pending"] == {"request": separate_id, "scope": "idle", "purpose": "original"}
    assert not reopened.attach(child_id, sign(child["request"], {"moving": "observed"}, owner))["alreadyFiled"]
    order = reopened.work_order_findings(incomplete["id"])
    assert reopened.work_order_findings(child_id) == order
    assert order["pending"] is None
    assert order["contexts"][0] == idle
    assert idle["evidence"]["receiptSha256"] == sha256(original.encode("ascii")).hexdigest()
    assert order["contexts"][1]["evidence"]["request"] == child_id
    assert order["contexts"][1]["evidence"]["finding"] == "observed"
    assert order["contexts"][1]["evidence"]["receiptSha256"] == sha256(
        reopened.fetch(child_id)["receipt"].encode("ascii")
    ).hexdigest()
    assert all(context["evidence"]["thresholdC"] == threshold for context in order["contexts"])
    assert order["contexts"][1]["pendingRequest"] is None
    assert order["fingerprint"] == sha256(owner.public_key().public_bytes_raw()).hexdigest()
    _, archive = reopened.work_order_archive(child_id)
    with ZipFile(BytesIO(archive)) as bundle:
        assert bundle.testzip() is None
        assert bundle.namelist() == [f"repair-verification-{request}.json" for request in (original_id, child_id)]
        for name, request in zip(bundle.namelist(), (incomplete, child["request"])):
            text = bundle.read(name).decode("ascii")
            assert local_reference not in text
            packet = json.loads(text)
            assert packet["format"] == "repair-receipt-verification/v1"
            assert packet["request"] == request
            assert packet["receipt"] == reopened.fetch(request["id"])["receipt"]
            assert packet["fingerprint"] == order["fingerprint"]
    assert reopened.job(parent_row)["workOrder"] == local_reference
    found = reopened.lookup(" " + local_reference + " ")
    assert [job["request"]["id"] for job in found["jobs"]] == [
        same_reference["request"]["id"], child_id, incomplete["id"],
    ]
    assert found["before"] is None
    for reference in (local_reference.lower(), local_reference[:-1], "' OR 1=1 --"):
        assert reopened.lookup(reference) == {"jobs": [], "before": None}
    for cursor in (True, 0, "1", 10**18):
        try:
            reopened.lookup(local_reference, cursor)
        except ValueError as error:
            assert str(error) == "Invalid page cursor."
        else:
            raise AssertionError("Lookup accepted an invalid page cursor.")

    extra_ids = [reopened.create("idle", pin(owner), local_reference)["request"]["id"]
                 for _ in range(PAGE_SIZE - 1)]
    reopened.create("idle", pin(owner), local_reference + "A")
    found = reopened.lookup(local_reference)
    earlier = reopened.lookup(local_reference, found["before"])
    assert len(found["jobs"]) == PAGE_SIZE and earlier["before"] is None
    assert [job["request"]["id"] for job in found["jobs"] + earlier["jobs"]] == [
        *reversed(extra_ids), same_reference["request"]["id"], child_id, incomplete["id"],
    ]
    snapshot_path = path.with_name("shop-backup.sqlite3")
    with closing(reopened.connect()) as uncommitted:
        uncommitted.execute("BEGIN IMMEDIATE")
        uncommitted.execute("UPDATE intake_requests SET work_order = ? WHERE id = ?",
                            ("Uncommitted update", same_reference["request"]["id"]))
        reopened.backup(snapshot_path)
        uncommitted.rollback()
    restored = ShopRegister(snapshot_path)
    with closing(restored.connect()) as db:
        assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert restored.fetch(same_reference["request"]["id"])["work_order"] == local_reference
    assert restored.fetch(incomplete["id"])["receipt"] == original
    assert restored.work_order_findings(child_id) == order
    assert restored.match(original)["state"] == "alreadyFiled"
    try:
        reopened.backup(snapshot_path)
    except FileExistsError:
        pass
    else:
        raise AssertionError("A new backup replaced an existing database.")
    interrupted = path.with_name("interrupted.sqlite3")
    with patch("shop_register.monotonic", side_effect=[0, 21]):
        try:
            reopened.backup(interrupted)
        except TimeoutError:
            assert not interrupted.exists()
        else:
            raise AssertionError("A timed-out backup left its output in place.")
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE intake_requests SET receipt = ? WHERE id = ?",
                   (sign(child["request"], {"moving": "not_observed"}, other), child_id))
    try:
        reopened.work_order_findings(incomplete["id"])
    except ValueError as error:
        assert str(error) == INVALID_SAVED_RECEIPT
        assert "does not match the issuer" in str(error.__cause__)
    else:
        raise AssertionError("An altered filed receipt entered the work-order findings.")
    try:
        reopened.work_order_archive(original_id)
    except ValueError as error:
        assert str(error) == INVALID_SAVED_RECEIPT
        assert "does not match the issuer" in str(error.__cause__)
    else:
        raise AssertionError("An altered filed receipt entered the work-order archive.")
    with closing(restored.connect()) as db, db:
        db.execute("UPDATE intake_requests SET work_order = ? WHERE id = ?", ("Different work order", child_id))
    try:
        restored.work_order_archive(original_id)
    except ValueError as error:
        assert "does not match its preceding receipt" in str(error)
    else:
        raise AssertionError("A misplaced follow-up entered the work-order archive.")
    initial = reopened.create("both", pin(owner), "Recheck case", threshold)["request"]
    try:
        reopened.repeat(initial["id"], recheck=True)
    except ValueError as error:
        assert "requires a filed receipt" in str(error)
    else:
        raise AssertionError("An open request created a recheck.")
    observed = sign(initial, {"idle": "observed", "moving": "not_observed"}, owner)
    reopened.attach(initial["id"], observed)
    recheck = reopened.repeat(initial["id"], recheck=True)
    assert reopened.repeat(initial["id"], recheck=True) == recheck
    after = recheck["request"]
    assert recheck["recheck"] and recheck["repeats"] == initial["id"]
    assert after == {**initial, "id": after["id"]} and after["id"] != initial["id"]
    order = reopened.work_order_findings(after["id"])
    assert order["pending"] == {"request": after["id"], "scope": "both", "purpose": "recheck"}
    pending = order["contexts"]
    assert all(entry["baseline"]["request"] == initial["id"] and entry["evidence"] is None for entry in pending)
    assert all(entry["pendingRequest"] == after["id"] for entry in pending)
    reopened.attach(after["id"], sign(after, {"idle": "not_observed", "moving": "insufficient_evidence"}, owner))
    follow_after = reopened.follow_up(after["id"])["request"]
    assert follow_after["scope"] == "moving"
    assert reopened.work_order_findings(initial["id"])["pending"] == {
        "request": follow_after["id"], "scope": "moving", "purpose": "follow-up",
    }
    reopened.attach(follow_after["id"], sign(follow_after, {"moving": "observed"}, owner))
    comparison = ShopRegister(path).work_order_findings(follow_after["id"])["contexts"]
    assert comparison[0]["baseline"]["finding"] == "observed"
    assert comparison[0]["evidence"]["finding"] == "not_observed"
    assert comparison[1]["baseline"]["request"] == initial["id"]
    assert comparison[1]["evidence"]["request"] == follow_after["id"]
    assert reopened.fetch(initial["id"])["receipt"] == observed
    _, history = reopened.work_order_archive(initial["id"])
    with ZipFile(BytesIO(history)) as bundle:
        assert bundle.namelist() == [f"repair-verification-{ticket['id']}.json"
                                    for ticket in (initial, after, follow_after)]

    full = reopened.repeat(follow_after["id"], recheck=True)["request"]
    assert full == {**initial, "id": full["id"]}
    prior_ids = [after["id"], follow_after["id"]]
    pending = reopened.work_order_findings(full["id"])["contexts"]
    assert [entry["baseline"]["request"] for entry in pending] == prior_ids
    assert all(entry["pendingRequest"] == full["id"] for entry in pending)
    reopened.attach(full["id"], sign(full, {"idle": "observed", "moving": "not_observed"}, owner))
    comparison = ShopRegister(path).work_order_findings(initial["id"])["contexts"]
    assert [entry["baseline"]["request"] for entry in comparison] == prior_ids
    assert all(entry["evidence"]["request"] == full["id"] for entry in comparison)
    _, history = reopened.work_order_archive(full["id"])
    with ZipFile(BytesIO(history)) as bundle:
        assert bundle.namelist() == [f"repair-verification-{ticket['id']}.json"
                                    for ticket in (initial, after, follow_after, full)]

    old = reopened.create("both", pin(owner), "Saved narrower recheck", threshold)["request"]
    reopened.attach(old["id"], sign(old, {"idle": "observed", "moving": "insufficient_evidence"}, owner))
    narrowed = reopened.follow_up(old["id"])["request"]
    reopened.attach(narrowed["id"], sign(narrowed, {"moving": "observed"}, owner))
    legacy = reopened.repeat(narrowed["id"], recheck=True)["request"]
    # Older releases saved the preceding request's scope when creating rechecks.
    with closing(reopened.connect()) as db, db:
        db.execute("UPDATE intake_requests SET scope = ? WHERE id = ?", ("moving", legacy["id"]))
    legacy = {**legacy, "scope": "moving"}
    reopened.attach(legacy["id"], sign(legacy, {"moving": "not_observed"}, owner))
    comparison = reopened.work_order_findings(old["id"])["contexts"]
    assert [entry["evidence"]["request"] for entry in comparison] == [old["id"], legacy["id"]]
    assert reopened.repeat(narrowed["id"], recheck=True)["request"] == legacy
    assert reopened.repeat(legacy["id"], recheck=True)["request"]["scope"] == "both"
    print("Verified matching, work-order evidence, full-scope rechecks, saved narrower rechecks, concurrency and backups.")

verify_archived_road_pair()
verify_create_retry()

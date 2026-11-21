"""Persistent shop requests and first-receipt acceptance."""

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import re
import secrets
import sqlite3
from time import monotonic
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from shop_request import (
    BENCH_SOURCE, CURRENT_RECIPE, FILE_SOURCES, MAX_TEMPERATURE_C, MIN_TEMPERATURE_C, RECEIPT_VERSIONS, RECIPE, SCOPES,
    STARTUP_RECIPE, canonical, matches_claim, request_document, valid_threshold, verification_packet,
)

PAGE_SIZE = 40
REGISTER_SCHEMA_VERSION = 2
INVALID_SAVED_RECEIPT = "The saved receipt failed verification. Check the original packet or a trusted backup."
WITHDRAWN_REQUEST = "This request was withdrawn. Open the replacement review for this work order."
RECIPE_COLUMN = (
    f"recipe TEXT NOT NULL DEFAULT '{RECIPE}' "
    f"CHECK(recipe IN ('{RECIPE}', '{CURRENT_RECIPE}', '{STARTUP_RECIPE}'))"
)
WORK_ORDER_COLUMN = "work_order TEXT CHECK(length(work_order) BETWEEN 1 AND 64)"
RECHECK_COLUMN = "recheck INTEGER NOT NULL DEFAULT 0 CHECK(recheck IN (0, 1) AND (recheck = 0 OR repeats IS NOT NULL))"
THRESHOLD_COLUMN = (
    "threshold_c INTEGER CHECK(threshold_c IS NULL OR "
    f"(typeof(threshold_c) = 'integer' AND threshold_c BETWEEN {MIN_TEMPERATURE_C} AND {MAX_TEMPERATURE_C}))"
)
# Keep the retired column while migrating registers with the former split recipe.
STARTUP_COLUMN = "startup_window INTEGER NOT NULL DEFAULT 0 CHECK(startup_window = 0)"
JOB_SELECT = """SELECT request.*, child.id AS follow_up, retired.id AS replaces_review
    FROM intake_requests AS request
    LEFT JOIN intake_requests AS child ON child.repeats = request.id
    LEFT JOIN intake_requests AS retired ON retired.superseded_by = request.id AND retired.repeats IS NULL"""


class ReceiptConflict(ValueError):
    """A request already has a different signed receipt."""


class RequestConflict(ValueError):
    """A request ID is already assigned to different request details."""


def utc_time():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_issuer(text):
    if not isinstance(text, str) or len(text) > 512:
        raise ValueError("Choose the enrolled issuer public key file.")
    pin = json.loads(text)
    if (not isinstance(pin, dict) or set(pin) != {"format", "ed25519"} or
            pin["format"] != "repair-receipt-issuer/v1" or not isinstance(pin["ed25519"], str) or
            not re.fullmatch(r"[a-f0-9]{64}", pin["ed25519"])):
        raise ValueError("The issuer key file is invalid.")
    return bytes.fromhex(pin["ed25519"])


def read_receipt(text):
    if not isinstance(text, str) or not 0 < len(text) <= 1024:
        raise ValueError("Choose a signed receipt JSON file.")
    record = json.loads(text)
    if not isinstance(record, dict) or record.get("format") not in (
            "repair-receipt/v2", "repair-receipt/v3", "repair-receipt/v5"):
        raise ValueError("Choose a signed receipt issued for a shop request.")
    claim = record.get("claim")
    request_id = claim.get("request") if isinstance(claim, dict) else None
    if not isinstance(request_id, str) or not re.fullmatch(r"[a-f0-9]{32}", request_id):
        raise ValueError("The receipt has an invalid shop request ID.")
    return record


def check_receipt(text, record, request, key):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("The enrolled issuer public key is invalid.")
    signature = record.get("signature")
    if not isinstance(signature, str) or not re.fullmatch(r"[a-f0-9]{128}", signature):
        raise ValueError("The receipt signature is invalid.")
    claim = record["claim"]
    version = RECEIPT_VERSIONS[record["format"]]
    source = None
    if version == 3:
        if request["recipe"] == STARTUP_RECIPE:
            raise ValueError("Use a recording for the startup window.")
        source = BENCH_SOURCE
    elif version == 5:
        source = claim.get("source")
        if not isinstance(source, str) or source not in FILE_SOURCES:
            raise ValueError("The receipt has an invalid recording source.")
    if not matches_claim(canonical(claim).encode("ascii"), request, source):
        raise ValueError("This receipt does not match the selected request or scope.")
    if text != canonical({"format": record["format"], "claim": claim, "signature": signature}):
        raise ValueError("The receipt contains unexpected fields or bytes.")
    try:
        domain = f"Repair Receipt v{version}\n".encode("ascii")
        Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(signature), domain + canonical(claim).encode("ascii"))
    except InvalidSignature as error:
        raise ValueError("The receipt signature does not match the issuer enrolled for this request.") from error
    return claim


def checked_saved_claim(row, ticket):
    text = row["receipt"]
    if text is None:
        return None
    try:
        return check_receipt(text, read_receipt(text), ticket, row["issuer"])
    except ValueError as error:
        raise ValueError(INVALID_SAVED_RECEIPT) from error


def missing_scope(claim):
    if claim is None:
        return None
    missing = [condition for condition in SCOPES[claim["scope"]][1]
               if claim[condition] == "insufficient_evidence"]
    return "both" if len(missing) == 2 else next(iter(missing), None)


def normalize_work_order(reference):
    if not isinstance(reference, str):
        raise ValueError("Enter a shop work order reference as text.")
    reference = reference.strip()
    if len(reference) > 64 or not reference.isprintable():
        raise ValueError("Use up to 64 printable characters for the work order reference.")
    return reference or None


def create_requests_table(db, table):
    db.execute(f"""CREATE TABLE {table} (
        number INTEGER PRIMARY KEY,
        id TEXT NOT NULL UNIQUE,
        scope TEXT NOT NULL CHECK(scope IN ('idle', 'moving', 'both')),
        issuer BLOB NOT NULL CHECK(length(issuer) = 32),
        created_at TEXT NOT NULL,
        receipt TEXT,
        accepted_at TEXT,
        {RECIPE_COLUMN},
        repeats TEXT REFERENCES {table}(id),
        {WORK_ORDER_COLUMN},
        {THRESHOLD_COLUMN},
        {RECHECK_COLUMN},
        {STARTUP_COLUMN},
        CHECK ((receipt IS NULL) = (accepted_at IS NULL))
    )""")


def migrate_requests(db):
    columns = {column["name"] for column in db.execute("PRAGMA table_info(intake_requests)")}
    recipe = "recipe" if "recipe" in columns else f"'{RECIPE}'"
    if "startup_window" in columns:
        recipe = f"CASE WHEN startup_window = 1 THEN '{STARTUP_RECIPE}' ELSE {recipe} END"
    repeats = "repeats" if "repeats" in columns else "NULL"
    work_order = "work_order" if "work_order" in columns else "NULL"
    threshold = "threshold_c" if "threshold_c" in columns else "NULL"
    recheck = "recheck" if "recheck" in columns else "0"
    create_requests_table(db, "intake_requests_migrated")
    db.execute(f"""INSERT INTO intake_requests_migrated (
        number, id, scope, issuer, created_at, receipt, accepted_at, recipe, repeats, work_order, threshold_c, recheck)
        SELECT number, id, scope, issuer, created_at, receipt, accepted_at,
               {recipe}, {repeats}, {work_order}, {threshold}, {recheck}
        FROM intake_requests""")
    if db.execute("PRAGMA foreign_key_check(intake_requests_migrated)").fetchone() is not None:
        raise sqlite3.IntegrityError("Saved request links could not be migrated.")
    db.execute("DROP TABLE intake_requests")
    db.execute("ALTER TABLE intake_requests_migrated RENAME TO intake_requests")


class ShopRegister:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as db, db:
            db.execute("PRAGMA foreign_keys = OFF")
            db.execute("BEGIN IMMEDIATE")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='intake_requests'").fetchone()
                if table:
                    migrate_requests(db)
                else:
                    create_requests_table(db, "intake_requests")
            elif version not in (1, REGISTER_SCHEMA_VERSION):
                raise ValueError("This backup uses an unsupported register schema.")
            if version < 2:
                db.execute("ALTER TABLE intake_requests ADD COLUMN superseded_by TEXT REFERENCES intake_requests(id)")
                db.execute(f"PRAGMA user_version = {REGISTER_SCHEMA_VERSION}")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS intake_one_follow_up ON intake_requests(repeats)")
            db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS intake_one_withdrawn_review
                ON intake_requests(superseded_by) WHERE repeats IS NULL AND superseded_by IS NOT NULL""")
            db.execute("""CREATE INDEX IF NOT EXISTS intake_work_order_lookup
                ON intake_requests(work_order, number) WHERE work_order IS NOT NULL""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS intake_withdrawn_read_only
                BEFORE UPDATE OF receipt, accepted_at ON intake_requests WHEN OLD.superseded_by IS NOT NULL
                BEGIN SELECT RAISE(ABORT, 'The request has been withdrawn.'); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS intake_withdrawn_no_follow_up
                BEFORE INSERT ON intake_requests WHEN EXISTS (
                    SELECT 1 FROM intake_requests WHERE id = NEW.repeats AND superseded_by IS NOT NULL
                )
                BEGIN SELECT RAISE(ABORT, 'The previous request has been withdrawn.'); END""")

    def connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def backup(self, destination: Path):
        with destination.open("xb"):
            pass
        deadline = monotonic() + 20

        def check_progress(_status, _remaining, _total):
            if monotonic() >= deadline:
                raise TimeoutError("The register backup did not finish in time.")

        try:
            with closing(self.connect()) as source, closing(sqlite3.connect(destination)) as snapshot:
                source.backup(snapshot, pages=128, progress=check_progress)
        except (OSError, sqlite3.Error):
            destination.unlink(missing_ok=True)
            raise

    @staticmethod
    def request(row):
        return request_document(row["scope"], row["id"], row["recipe"], row["threshold_c"])

    @classmethod
    def job(cls, row):
        request = cls.request(row)
        issuer = row["issuer"]
        fingerprint = sha256(issuer).hexdigest() if isinstance(issuer, bytes) and len(issuer) == 32 else None
        try:
            claim = checked_saved_claim(row, request)
            receipt_invalid = False
        except ValueError:
            claim = None
            receipt_invalid = True
        return {
            "request": request,
            "createdAt": row["created_at"],
            "acceptedAt": None if receipt_invalid else row["accepted_at"],
            "fingerprint": fingerprint,
            "claim": claim,
            "receiptInvalid": receipt_invalid,
            "repeats": row["repeats"],
            "recheck": bool(row["recheck"]),
            "followUp": row["follow_up"],
            "missingScope": missing_scope(claim),
            "workOrder": row["work_order"],
            "supersededBy": row["superseded_by"],
            "replacesReview": row["replaces_review"],
        }

    @classmethod
    def checked_job(cls, row):
        job = cls.job(row)
        if job["receiptInvalid"]:
            raise ValueError(INVALID_SAVED_RECEIPT)
        return job

    @staticmethod
    def find(db, request_id):
        row = db.execute(JOB_SELECT + " WHERE request.id = ?", (request_id,)).fetchone()
        if row is None:
            raise KeyError("This request was not found in the shop register.")
        return row

    def create(self, scope, issuer_file, work_order=None, threshold=None, *, recipe=CURRENT_RECIPE, request_id=None):
        if not isinstance(scope, str) or scope not in SCOPES:
            raise ValueError("Choose a supported operating condition.")
        if recipe not in (CURRENT_RECIPE, STARTUP_RECIPE):
            raise ValueError("Choose a supported recording window.")
        key = read_issuer(issuer_file)
        if work_order is not None:
            work_order = normalize_work_order(work_order)
        if threshold is not None and not valid_threshold(threshold):
            raise ValueError(f"Enter a whole temperature between {MIN_TEMPERATURE_C} and {MAX_TEMPERATURE_C} °C.")
        if request_id is None:
            request_id = secrets.token_hex(16)
        elif not isinstance(request_id, str) or not re.fullmatch(r"[a-f0-9]{32}", request_id):
            raise ValueError("The request ID is invalid.")
        with closing(self.connect()) as db, db:
            db.execute("""INSERT INTO intake_requests(
                id, scope, issuer, created_at, recipe, work_order, threshold_c)
                VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING""",
                       (request_id, scope, key, utc_time(), recipe, work_order, threshold))
            row = self.find(db, request_id)
            saved = self.request(row), row["issuer"], row["work_order"]
            expected = request_document(scope, request_id, recipe, threshold), key, work_order
            if row["repeats"] is not None or saved != expected:
                raise RequestConflict("This request ID is already registered with different details.")
            return self.checked_job(row)

    def follow_up(self, request_id):
        return self.repeat(request_id, recheck=False)

    def repeat(self, request_id, *, recheck):
        if not isinstance(request_id, str) or not re.fullmatch(r"[a-f0-9]{32}", request_id):
            raise ValueError("Choose a request from the shop register.")
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = self.find(db, request_id)
            if row["superseded_by"]:
                raise RequestConflict(WITHDRAWN_REQUEST)
            prior = self.request(row)
            claim = checked_saved_claim(row, prior)
            missing = missing_scope(claim)
            if recheck and (claim is None or missing):
                raise ValueError("A recheck requires a filed receipt with a finding for every requested condition.")
            if not recheck and missing is None:
                raise ValueError("A follow-up requires a filed receipt with insufficient evidence.")
            if row["follow_up"]:
                child = self.find(db, row["follow_up"])
                if bool(child["recheck"]) != recheck:
                    raise ValueError("The saved repeat has a different purpose.")
                return self.checked_job(child)
            scope = self._checked_work_order(db, request_id)[0][1]["scope"] if recheck else missing
            follow_up = secrets.token_hex(16)
            db.execute("""INSERT INTO intake_requests(
                id, scope, issuer, created_at, recipe, repeats, work_order, threshold_c, recheck)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (follow_up, scope, row["issuer"], utc_time(), row["recipe"],
                    request_id, row["work_order"], row["threshold_c"], recheck))
            return self.job(self.find(db, follow_up))

    def replace_review(self, request_id):
        if not isinstance(request_id, str) or not re.fullmatch(r"[a-f0-9]{32}", request_id):
            raise ValueError("Choose a work order from the shop register.")
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            chain = self._checked_work_order(db, request_id)
            root, _, _ = chain[0]
            if root["superseded_by"]:
                return self.checked_job(self.find(db, root["superseded_by"]))
            if not any(claim is not None for _, _, claim in chain):
                raise ValueError("File a receipt before withdrawing this review.")
            replacement = secrets.token_hex(16)
            db.execute("""INSERT INTO intake_requests(
                id, scope, issuer, created_at, recipe, work_order, threshold_c)
                VALUES (?, ?, ?, ?, ?, ?, ?)""", (replacement, root["scope"], root["issuer"], utc_time(),
                    root["recipe"], root["work_order"], root["threshold_c"]))
            db.executemany("UPDATE intake_requests SET superseded_by = ? WHERE id = ?",
                           ((replacement, row["id"]) for row, _, _ in chain))
            return self.job(self.find(db, replacement))

    def list(self, before=None, work_order=None):
        filters, values = [], []
        if work_order is not None:
            filters.append("request.work_order = ?")
            values.append(work_order)
        if before is not None:
            filters.append("request.number < ?")
            values.append(before)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        with closing(self.connect()) as db:
            rows = db.execute(JOB_SELECT + where + " ORDER BY request.number DESC LIMIT ?",
                              (*values, PAGE_SIZE + 1)).fetchall()
        visible = rows[:PAGE_SIZE]
        return {"jobs": [self.job(row) for row in visible],
                "before": visible[-1]["number"] if len(rows) > PAGE_SIZE else None}

    def lookup(self, reference, before=None):
        work_order = normalize_work_order(reference)
        if work_order is None:
            raise ValueError("Enter the full work order reference.")
        if before is not None and (type(before) is not int or not 1 <= before < 10**18):
            raise ValueError("Invalid page cursor.")
        return self.list(before, work_order)

    def fetch(self, request_id):
        with closing(self.connect()) as db:
            return self.find(db, request_id)

    def checked_work_order(self, request_id):
        with closing(self.connect()) as db:
            return self._checked_work_order(db, request_id)

    def _checked_work_order(self, db, request_id):
        rows = db.execute("""WITH RECURSIVE
            ancestors(id, repeats) AS (
                SELECT id, repeats FROM intake_requests WHERE id = ?
                UNION
                SELECT parent.id, parent.repeats FROM intake_requests AS parent
                    JOIN ancestors ON parent.id = ancestors.repeats
            ),
            linked(id) AS (
                SELECT id FROM ancestors WHERE repeats IS NULL
                UNION
                SELECT child.id FROM intake_requests AS child JOIN linked ON child.repeats = linked.id
            )
            SELECT request.* FROM intake_requests AS request JOIN linked USING(id)
            ORDER BY request.number""", (request_id,)).fetchall()
        if not rows:
            raise KeyError("This request was not found in the shop register.")
        root = rows[0]
        review_fields = ("issuer", "recipe", "threshold_c", "work_order")
        if root["superseded_by"]:
            replacement = self.find(db, root["superseded_by"])
            if (replacement["number"] <= root["number"] or replacement["repeats"] is not None or
                    any(replacement[field] != root[field] for field in (*review_fields, "scope"))):
                raise ValueError("The saved replacement does not match the withdrawn review.")
        same_fields = (*review_fields, "superseded_by")
        checked = []
        for row in rows:
            request = self.request(row)
            if checked:
                _, previous, preceding_claim = checked[-1]
                missing = missing_scope(preceding_claim)
                scopes = (missing,)
                if row["recheck"]:
                    # Older registers used the preceding request's scope for a recheck.
                    scopes = (previous["scope"], root["scope"]) if preceding_claim is not None and missing is None else ()
                if (row["repeats"] != previous["id"] or request["scope"] not in scopes or
                        any(row[field] != root[field] for field in same_fields)):
                    raise ValueError("A saved follow-up does not match its preceding receipt.")
            claim = checked_saved_claim(row, request)
            checked.append((row, request, claim))
        return checked

    def work_order_findings(self, request_id):
        with closing(self.connect()) as db, db:
            db.execute("BEGIN")
            chain = self._checked_work_order(db, request_id)
            root = self.find(db, chain[0][0]["id"])
        contexts = {condition: {"condition": condition, "evidence": None, "pendingRequest": None}
                    for condition in SCOPES[root["scope"]][1]}
        for row, request, claim in chain:
            receipt_digest = sha256(row["receipt"].encode("ascii")).hexdigest() if claim else None
            for condition in SCOPES[request["scope"]][1]:
                context = contexts[condition]
                if row["recheck"]:
                    context["baseline"] = context["evidence"]
                    context["evidence"] = None
                context["pendingRequest"] = None if claim else request["id"]
                if claim:
                    context["evidence"] = {"finding": claim[condition], "request": request["id"],
                                           "recipe": request["recipe"], "source": claim.get("source"),
                                           "thresholdC": claim.get("thresholdC"),
                                           "filedAt": row["accepted_at"], "receiptSha256": receipt_digest}
        latest, latest_request, latest_claim = chain[-1]
        pending = None
        missing = missing_scope(latest_claim)
        follow_up = {"request": latest_request["id"], "scope": missing} if missing else None
        if latest_claim is None:
            purpose = "recheck" if latest["recheck"] else "follow-up" if latest["repeats"] else "original"
            pending = {"request": latest_request["id"], "scope": latest_request["scope"], "purpose": purpose}
        visible_receipts = {
            reading["request"] for context in contexts.values()
            for reading in (context["evidence"], context.get("baseline")) if reading is not None
        }
        earlier_receipts = [
            {"request": request["id"], "filedAt": row["accepted_at"],
             "findings": {condition: claim[condition] for condition in SCOPES[request["scope"]][1]}}
            for row, request, claim in reversed(chain)
            if claim is not None and request["id"] not in visible_receipts
        ]
        return {"workOrder": root["work_order"], "originalRequest": root["id"],
                "fingerprint": sha256(root["issuer"]).hexdigest(), "contexts": list(contexts.values()),
                "pending": None if root["superseded_by"] else pending,
                "nextFollowUp": None if root["superseded_by"] else follow_up, "earlierReceipts": earlier_receipts,
                "scope": root["scope"], "supersededBy": root["superseded_by"], "replacesReview": root["replaces_review"]}

    def work_order_archive(self, request_id):
        chain = self.checked_work_order(request_id)
        root, _, root_claim = chain[0]
        if root["superseded_by"]:
            raise ValueError(WITHDRAWN_REQUEST)
        if root_claim is None:
            raise ValueError("File a signed receipt before downloading work-order evidence.")
        output = BytesIO()
        fingerprint = sha256(root["issuer"]).hexdigest()
        with ZipFile(output, "w") as archive:
            for row, request, claim in chain:
                if claim is None:
                    continue
                packet = verification_packet(request, row["receipt"], fingerprint)
                filename = ZipInfo(f"repair-verification-{request['id']}.json")
                archive.writestr(filename, canonical(packet), compress_type=ZIP_DEFLATED)
        return root["id"], output.getvalue()

    def match(self, text, *, packet=None):
        record = read_receipt(text)
        row = self.fetch(record["claim"]["request"])
        if row["superseded_by"]:
            raise RequestConflict(WITHDRAWN_REQUEST)
        job = self.checked_job(row)
        request = job["request"]
        if packet is not None:
            if canonical(packet["request"]) != canonical(request):
                raise ValueError("The packet request does not match the original shop request.")
            if packet["fingerprint"] != job["fingerprint"]:
                raise ValueError("The packet fingerprint does not match the enrolled issuer for this request.")
        claim = check_receipt(text, record, request, row["issuer"])
        state = "ready" if row["receipt"] is None else "alreadyFiled" if row["receipt"] == text else "conflict"
        return {"job": job, "claim": claim, "state": state}

    def attach(self, request_id, text):
        if not isinstance(request_id, str) or not re.fullmatch(r"[a-f0-9]{32}", request_id):
            raise ValueError("Choose a request from the shop register.")
        job = self.fetch(request_id)
        check_receipt(text, read_receipt(text), self.request(job), job["issuer"])
        with closing(self.connect()) as db, db:
            written = db.execute("""UPDATE intake_requests
                SET receipt = ?, accepted_at = ?
                WHERE id = ? AND receipt IS NULL AND superseded_by IS NULL""", (text, utc_time(), request_id)).rowcount
            current = self.find(db, request_id)
            if current["superseded_by"]:
                raise RequestConflict(WITHDRAWN_REQUEST)
            saved = self.checked_job(current)
            if not written and current["receipt"] != text:
                raise ReceiptConflict("A different signed receipt has already been filed for this request.")
            return {"job": saved, "alreadyFiled": not written}

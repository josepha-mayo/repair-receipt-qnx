"""Validate the portable shop request and the corresponding QNX claim."""

from hashlib import sha256
import json
import re

RECIPE = "coolant-context-demo/v1"
CURRENT_RECIPE = "coolant-duration-demo/v2"
STARTUP_RECIPE = "coolant-startup-window/v3"
RECIPES = {RECIPE: 1, CURRENT_RECIPE: 2, STARTUP_RECIPE: 4}
DEFAULT_THRESHOLD_C = 105
MIN_TEMPERATURE_C, MAX_TEMPERATURE_C = -40, 200
REQUEST_FORMAT = "repair-receipt-request/v1"
THRESHOLD_REQUEST_FORMAT = "repair-receipt-request/v2"
PACKET_FORMAT = "repair-receipt-verification/v1"
BENCH_SOURCE = "obd-bench/v1"
UPLOADED_SOURCE = "uploaded-csv/v1"
DEMO_SOURCE = "demo-fixture/v1"
PUBLISHED_SOURCE = "published-road/v1"
# These bytes prefix sourced CSVs inside the authenticated staging payload.
FILE_SOURCES = {UPLOADED_SOURCE: b"\x01", DEMO_SOURCE: b"\x02", PUBLISHED_SOURCE: b"\x03"}
RECEIPT_VERSIONS = {f"repair-receipt/v{version}": version for version in range(1, 7)}
SCOPES = {"idle": (1, ("idle",)), "moving": (2, ("moving",)), "both": (3, ("idle", "moving"))}
FINDINGS = {"observed", "not_observed", "insufficient_evidence"}


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


def request_fingerprint(request):
    return sha256(canonical(request).encode("ascii")).hexdigest()


def verification_packet(request, receipt, fingerprint):
    return {"format": PACKET_FORMAT, "request": request, "receipt": receipt, "fingerprint": fingerprint}


def signed_receipt_format(request, source):
    if source == BENCH_SOURCE:
        return "repair-receipt/v3"
    if source is not None:
        return "repair-receipt/v5" if request is not None else "repair-receipt/v6"
    return "repair-receipt/v2" if request is not None else "repair-receipt/v4"


def consent_export_size(claim, request, fingerprint):
    receipt = canonical({"format": signed_receipt_format(request, claim.get("source")),
                         "claim": claim, "signature": "0" * 128})
    if request is None:
        return len(receipt)
    return len(canonical(verification_packet(request, receipt, fingerprint)))


def valid_threshold(value):
    return type(value) is int and MIN_TEMPERATURE_C <= value <= MAX_TEMPERATURE_C


def request_document(scope, request_id, recipe, threshold=None):
    value = {"format": REQUEST_FORMAT if threshold is None else THRESHOLD_REQUEST_FORMAT,
             "recipe": recipe, "scope": scope, "id": request_id}
    if threshold is not None:
        value["thresholdC"] = threshold
    return value


def parse_request(text):
    if len(text) > 256:
        raise ValueError("This file exceeds the shop request size limit.")
    value = json.loads(text)
    if (not isinstance(value, dict) or value.get("format") not in (REQUEST_FORMAT, THRESHOLD_REQUEST_FORMAT) or
            not isinstance(value.get("recipe"), str) or value["recipe"] not in RECIPES or
            not isinstance(value.get("scope"), str) or
            value["scope"] not in SCOPES or not isinstance(value.get("id"), str) or
            not re.fullmatch(r"[0-9a-f]{32}", value["id"])):
        raise ValueError("Unsupported shop request.")
    threshold = None
    if value["format"] == THRESHOLD_REQUEST_FORMAT:
        threshold = value.get("thresholdC")
        if value["recipe"] not in (CURRENT_RECIPE, STARTUP_RECIPE) or not valid_threshold(threshold):
            raise ValueError("The shop request has an invalid temperature threshold.")
    expected = request_document(value["scope"], value["id"], value["recipe"], threshold)
    if canonical(expected) != text:
        raise ValueError("The shop request contains unexpected fields or bytes.")
    return expected


def guest_bytes(request):
    prefix = bytes((SCOPES[request["scope"]][0],)) + bytes.fromhex(request["id"])
    if "thresholdC" in request:
        encoding = 5 if request["recipe"] == STARTUP_RECIPE else 3
        return prefix + bytes((encoding, request["thresholdC"] - MIN_TEMPERATURE_C))
    version = RECIPES[request["recipe"]]
    return prefix if version == 1 else prefix + bytes((version,))


def matches_findings(preview, expected, fields):
    value = json.loads(preview)
    if not isinstance(value, dict):
        return False
    for field in fields:
        answer = value.get(field)
        if not isinstance(answer, str) or answer not in FINDINGS:
            return False
        expected[field] = answer
    return canonical(expected).encode("ascii") == preview


def matches_claim(preview, request, source=None):
    scope = request["scope"]
    expected = {"recipe": request["recipe"]}
    if "thresholdC" in request:
        expected["thresholdC"] = request["thresholdC"]
    if source is not None:
        expected["source"] = source
    expected.update(request=request["id"], scope=scope)
    return matches_findings(preview, expected, SCOPES[scope][1])


def matches_driver_claim(preview, source=None):
    expected = {"recipe": CURRENT_RECIPE}
    if source is not None:
        expected["source"] = source
    return matches_findings(preview, expected, SCOPES["both"][1])

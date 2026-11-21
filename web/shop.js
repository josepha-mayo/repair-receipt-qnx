"use strict";

const byId = id => document.getElementById(id);
const receiptFile = byId("receipt-file");
const issuerFile = byId("issuer-file");
const expectedIssuer = byId("expected-issuer");
const requestFile = byId("expected-request");
const verifyButton = byId("verify");
const result = byId("result");
const resultCard = byId("result-card");
const receiptDigestInput = byId("filed-receipt-digest");
const batchResults = byId("batch-results");
const digestSearch = byId("filed-receipt-search");
const sha256Hex = /^[a-f0-9]{64}$/;
const zipExtension = /\.zip$/i;
const labels = new Map([
  ["observed", "Observed"],
  ["not_observed", "Not observed"],
  ["insufficient_evidence", "Insufficient evidence"],
]);
const receiptVersions = new Map([
  ["repair-receipt/v1", 1], ["repair-receipt/v2", 2], ["repair-receipt/v3", 3], ["repair-receipt/v4", 4],
  ["repair-receipt/v5", 5], ["repair-receipt/v6", 6],
]);
let generation = 0;
let pendingRequest = 0;
let expected = null;
let requestLoading = false;
let requestError = "";
let keySelection = 0;

function update(text, outcome = "", verifiedReceipt = outcome === "good") {
  result.textContent = text;
  result.className = "status " + outcome;
  batchResults.hidden = true;
  digestSearch.hidden = true;
  byId("filed-receipt-status").textContent = "";
  byId("batch-warning").hidden = true;
  byId("findings").hidden = !verifiedReceipt;
  byId("evidence-details").hidden = !verifiedReceipt;
  byId("intake-actions").hidden = !verifiedReceipt;
  resultCard.classList.toggle("verified-receipt", verifiedReceipt);
  delete resultCard.dataset.receiptDigest;
  byId("matched-request").hidden = true;
  byId("included-request-note").hidden = true;
  byId("issuer-match").hidden = true;
  byId("print-request").hidden = true;
  byId("print-digest").hidden = true;
  byId("print-issuer").hidden = true;
}

async function publicVerifier(issuer, expectedFingerprint = "") {
  const expected = expectedFingerprint.replace(/\s+/g, "").toLowerCase();
  if (expected && !sha256Hex.test(expected)) {
    throw new Error("Enter a full 64-character SHA-256 fingerprint.");
  }
  const {key: rawKey} = await ShopRequest.readIssuer(issuer);
  const issuerFingerprint = await ShopRequest.fingerprint(rawKey);
  if (expected && expected !== issuerFingerprint) {
    throw new Error("Issuer fingerprint mismatch. Check the key file against the fingerprint you received separately.");
  }
  try {
    const key = await crypto.subtle.importKey("raw", rawKey, "Ed25519", false, ["verify"]);
    return {key, issuerFingerprint, fingerprintMatched: !!expected};
  } catch {
    throw new Error("This browser could not load the Ed25519 key. Try a current Chromium browser.");
  }
}

async function verifyEvidence(evidence, {key, issuerFingerprint}, ticket) {
  const {receiptText, packetRequest, fingerprint} = evidence;
  const matchedIncludedRequest = !!packetRequest && !ticket;
  if (packetRequest) {
    if (ticket && JSON.stringify(ticket) !== JSON.stringify(packetRequest)) {
      throw new Error("The packet includes a different request from the one you selected.");
    }
    ticket = packetRequest;
    if (fingerprint !== issuerFingerprint) {
      throw new Error("The packet fingerprint does not match your trusted issuer key.");
    }
  }
  let record;
  try {
    record = JSON.parse(receiptText);
  } catch {
    throw new Error("Choose a Repair Receipt JSON file and its separate issuer key.");
  }
  const claim = record?.claim;
  const version = receiptVersions.get(record?.format);
  const bench = version === 3;
  const sourced = version === 5 || version === 6;
  const driverStarted = version === 4 || version === 6;
  const bound = bench || version === 2 || version === 5;
  if (!version || typeof claim?.recipe !== "string" || !Object.hasOwn(ShopRequest.recipes, claim.recipe) ||
      (version === 1 && claim.recipe !== ShopRequest.legacyRecipe) ||
      (driverStarted && claim.recipe !== ShopRequest.recipe) ||
      (claim.recipe === ShopRequest.startupRecipe && (!bound || bench)) ||
      typeof record.signature !== "string" || !/^[0-9a-f]{128}$/.test(record.signature)) {
    throw new Error("The receipt format or findings are invalid.");
  }
  const canonicalClaim = {recipe: claim.recipe};
  if (Object.hasOwn(claim, "thresholdC")) {
    if (!bound || !ShopRequest.supportsThreshold(claim.recipe) || !ShopRequest.validThreshold(claim.thresholdC)) {
      throw new Error("The receipt has an invalid temperature threshold.");
    }
    canonicalClaim.thresholdC = claim.thresholdC;
  }
  if (bench || sourced) {
    const valid = bench ? claim.source === ShopRequest.benchSource
      : typeof claim.source === "string" && Object.hasOwn(ShopRequest.fileSources, claim.source);
    if (!valid) throw new Error("The capture source is invalid.");
    canonicalClaim.source = claim.source;
  }
  if (bound) {
    if (typeof claim.request !== "string" || !/^[0-9a-f]{32}$/.test(claim.request) ||
        typeof claim.scope !== "string" || !Object.hasOwn(ShopRequest.scopes, claim.scope)) {
      throw new Error("The receipt request binding is invalid.");
    }
    canonicalClaim.request = claim.request;
    canonicalClaim.scope = claim.scope;
  }
  for (const field of ["idle", "moving"]) {
    if (bound && claim.scope !== "both" && claim.scope !== field) continue;
    if (!labels.has(claim[field])) throw new Error("A requested finding is missing or invalid.");
    canonicalClaim[field] = claim[field];
  }
  const envelope = {format: record.format, claim: canonicalClaim, signature: record.signature};
  if (receiptText !== JSON.stringify(envelope)) {
    throw new Error("The receipt contains unexpected bytes or fields.");
  }
  const message = new TextEncoder().encode(`Repair Receipt v${version}\n` + JSON.stringify(canonicalClaim));
  if (!await crypto.subtle.verify("Ed25519", key, ShopRequest.hexBytes(record.signature), message)) {
    throw new Error("Signature mismatch. The receipt was changed or the issuer key is different.");
  }
  if (bound && !ticket) throw new Error("Load the original shop request to verify this receipt.");
  if (ticket && (!bound || ticket.id !== claim.request || ticket.scope !== claim.scope ||
      ticket.recipe !== claim.recipe || ticket.thresholdC !== claim.thresholdC)) {
    throw new Error("This receipt answers a different request.");
  }
  const receiptSha256 = await ShopRequest.fingerprint(new TextEncoder().encode(receiptText));
  return {claim: canonicalClaim, issuerFingerprint, receiptSha256, matchedIncludedRequest, driverStarted};
}

function resetVerification() {
  ++generation;
  const archive = [...receiptFile.files].some(file => zipExtension.test(file.name));
  const batch = archive || receiptFile.files.length > 1;
  const error = archive && receiptFile.files.length !== 1 ? "Choose one work-order ZIP or select the JSON packets."
    : batch ? "" : requestError;
  const ready = receiptFile.files.length && issuerFile.files.length && !error && (batch || !requestLoading);
  byId("request-selection").hidden = batch;
  byId("clear-expected").hidden = !expected && !requestLoading && !requestError;
  byId("batch-mode-help").hidden = !batch || !!error;
  verifyButton.textContent = archive ? "Verify work-order ZIP" : batch ? "Verify packets" : "Verify receipt";
  verifyButton.disabled = !ready;
  update(error || (ready ? "Ready to verify." : "Waiting for a receipt and key."), error ? "bad" : "");
  byId("expected-status").textContent = expected
    ? `${ShopRequest.scopes[expected.scope]} · Request ${expected.id.slice(-8)}`
    : "Load the work order’s original request to confirm a specific job. A packet includes its own request.";
}

for (const input of [receiptFile, issuerFile]) {
  input.addEventListener("change", resetVerification);
}
expectedIssuer.addEventListener("input", resetVerification);

issuerFile.addEventListener("change", async () => {
  const version = ++keySelection;
  const label = byId("pin-fingerprint");
  label.hidden = true;
  if (!issuerFile.files.length) return;
  try {
    const {key} = await ShopRequest.readIssuer(issuerFile.files[0]);
    const hex = await ShopRequest.fingerprint(key);
    if (version !== keySelection) return;
    label.textContent = `SHA-256 fingerprint ${hex.match(/.{8}/g).join(" ")}`;
    label.hidden = false;
  } catch {
    // Verification reports a malformed key when the shop checks the receipt.
  }
});

async function loadExpectedRequest() {
  const version = ++pendingRequest;
  expected = null;
  requestError = "";
  requestLoading = !!requestFile.files.length;
  resetVerification();
  if (!requestLoading) return;
  try {
    const parsed = await ShopRequest.load(requestFile.files[0]);
    if (version === pendingRequest) expected = parsed;
  } catch (error) {
    if (version === pendingRequest) requestError = error.message;
  } finally {
    if (version === pendingRequest) {
      requestLoading = false;
      resetVerification();
    }
  }
}

requestFile.addEventListener("change", loadExpectedRequest);
byId("clear-expected").addEventListener("click", () => {
  requestFile.value = "";
  loadExpectedRequest();
  requestFile.focus();
});

byId("create-request").addEventListener("click", async () => {
  const threshold = byId("offline-threshold");
  if (!threshold.reportValidity()) return;
  const version = ++pendingRequest;
  requestFile.value = "";
  requestError = "";
  requestLoading = false;
  const created = ShopRequest.create(byId("scope-select").value, threshold.value === "" ? null : threshold.valueAsNumber,
    byId("offline-window").value);
  expected = created;
  const fingerprint = byId("created-request-fingerprint");
  fingerprint.hidden = true;
  ShopRequest.save("repair-request.json", JSON.stringify(created));
  resetVerification();
  const digest = await ShopRequest.requestFingerprint(created);
  if (version === pendingRequest) {
    fingerprint.hidden = false;
    fingerprint.textContent = `Request SHA-256 ${digest}`;
  }
});

byId("print-finding").addEventListener("click", () => window.print());

function findFiledReceipt() {
  if (digestSearch.hidden) return;
  const input = receiptDigestInput.value.trim();
  const digest = input.replace(/^receipt\s+sha-256\s+/i, "").replace(/\s+/g, "").toLowerCase();
  const valid = sha256Hex.test(digest);
  const singleDigest = resultCard.dataset.receiptDigest;
  let matches = 0;
  let filename = "";
  for (const row of batchResults.hidden ? [] : batchResults.querySelectorAll("[data-receipt-digest]")) {
    const match = valid && row.dataset.receiptDigest === digest;
    row.querySelector(".batch-match").hidden = !match;
    if (match) {
      matches++;
      filename = row.dataset.attachmentName;
    }
  }
  const status = byId("filed-receipt-status");
  let message = "";
  if (input) {
    if (!valid) message = "Enter the full 64-character receipt digest.";
    else if (singleDigest) {
      message = singleDigest === digest
        ? "This signed receipt matches the work-order digest."
        : "This signed receipt differs from the work-order digest.";
    } else if (!matches) message = "No verified attachment matches that digest.";
    else message = matches === 1 ? `Matching attachment · ${filename}` : `${matches} verified attachments match.`;
  }
  if (status.textContent !== message) status.textContent = message;
}

receiptDigestInput.addEventListener("input", findFiledReceipt);

async function verifyBatch(files, verifier, attempt, fromArchive = false) {
  const rows = document.createDocumentFragment();
  const requests = new Map();
  let verified = 0;
  for (const file of files) {
    if (attempt !== generation) return;
    const row = byId("batch-result").content.cloneNode(true);
    const heading = row.querySelector(".batch-file");
    const summary = row.querySelector(".batch-summary");
    try {
      const evidence = await ShopRequest.readEvidence(file);
      if (!evidence.packetRequest) throw new Error("This file needs a verification packet with the original request.");
      const {claim, receiptSha256} = await verifyEvidence(evidence, verifier, null);
      if (fromArchive && file.name !== `repair-verification-${claim.request}.json`) {
        throw new Error("The archive filename does not match the signed request ID.");
      }
      const item = row.querySelector("li");
      item.dataset.receiptDigest = receiptSha256;
      item.dataset.attachmentName = file.name;
      const attachment = row.querySelector(".batch-attachment");
      attachment.textContent = `Attachment · ${file.name}`;
      attachment.hidden = false;
      heading.textContent = `Request ${claim.request}`;
      summary.textContent = [claim.idle && `At idle · ${labels.get(claim.idle)}`,
        claim.moving && `While moving · ${labels.get(claim.moving)}`].filter(Boolean).join(" · ");
      const rule = row.querySelector(".batch-rule");
      rule.textContent = ShopRequest.rule(claim);
      rule.hidden = false;
      const source = row.querySelector(".batch-source");
      source.textContent = ShopRequest.sourceLabel(claim.source);
      source.hidden = false;
      const digest = row.querySelector(".batch-digest");
      digest.textContent = `Receipt SHA-256 ${receiptSha256}`;
      digest.hidden = false;
      if (!requests.has(claim.request)) requests.set(claim.request, {digests: new Set(), notices: []});
      const group = requests.get(claim.request);
      group.digests.add(receiptSha256);
      group.notices.push({field: attachment, filename: file.name});
      verified++;
    } catch (error) {
      heading.textContent = file.name;
      summary.textContent = error.message;
      summary.classList.add("bad");
    }
    rows.append(row);
  }
  if (attempt !== generation) return;
  let conflicts = 0;
  for (const {digests, notices} of requests.values()) {
    if (digests.size < 2) continue;
    conflicts++;
    for (const {field, filename} of notices) {
      field.textContent = `Compare attachment · ${filename}`;
    }
  }
  const outcome = verified !== files.length ? "bad" : conflicts ? "" : "good";
  const message = files.length === 1 ? (verified ? "Verified 1 packet." : "No packets verified.")
    : `Verified ${verified} of ${files.length} packets.`;
  update(message, outcome, false);
  byId("issuer-match").hidden = !verifier.fingerprintMatched;
  if (conflicts) {
    const warning = byId("batch-warning");
    const subject = conflicts === 1 ? "One request has" : `${conflicts} requests have`;
    warning.textContent = `${subject} different signed receipts. Match the receipt SHA-256 to the filed work order.`;
    warning.hidden = false;
  }
  batchResults.replaceChildren(rows);
  batchResults.hidden = false;
  digestSearch.hidden = !verified;
  findFiledReceipt();
}

verifyButton.addEventListener("click", async () => {
  const attempt = ++generation;
  const files = [...receiptFile.files];
  const issuer = issuerFile.files[0];
  const ticket = expected;
  const archive = files.length === 1 && zipExtension.test(files[0].name);
  const batch = archive || files.length > 1;
  const moveFocus = document.activeElement === verifyButton;
  verifyButton.disabled = true;
  update(batch ? "Checking each signature." : "Checking the signature.");
  try {
    const verifier = await publicVerifier(issuer, expectedIssuer.value);
    if (attempt !== generation) return;
    if (batch) {
      const packets = archive ? await WorkOrderArchive.open(files[0], () => attempt === generation) : files;
      if (attempt === generation) await verifyBatch(packets, verifier, attempt, archive);
      return;
    }
    const {claim, issuerFingerprint, receiptSha256, matchedIncludedRequest, driverStarted} =
      await verifyEvidence(await ShopRequest.readEvidence(files[0]), verifier, ticket);
    if (attempt !== generation) return;
    for (const field of ["idle", "moving"]) {
      byId(field + "-row").hidden = !Object.hasOwn(claim, field);
      byId(field).textContent = labels.get(claim[field]) || "";
    }
    byId("coverage-note").hidden = ![claim.idle, claim.moving].includes("insufficient_evidence");
    byId("evidence-rule").textContent = ShopRequest.rule(claim);
    byId("evidence-input").textContent = ShopRequest.sourceLabel(claim.source);
    byId("coverage-note").textContent =
      "Insufficient evidence means there was too little usable coverage in that condition or a gap in the recording.";
    const requestStatus = driverStarted ? " Driver-started review." :
      matchedIncludedRequest ? " Included request matched." : claim.request ? " Request matched." : "";
    update("Signature verified." + requestStatus, "good");
    resultCard.dataset.receiptDigest = receiptSha256;
    digestSearch.hidden = false;
    findFiledReceipt();
    byId("issuer-match").hidden = !verifier.fingerprintMatched;
    byId("included-request-note").hidden = !matchedIncludedRequest;
    const printIssuer = byId("print-issuer");
    printIssuer.textContent = `Issuer key SHA-256 ${issuerFingerprint}`;
    printIssuer.hidden = false;
    const printDigest = byId("print-digest");
    printDigest.textContent = `Receipt SHA-256 ${receiptSha256}`;
    printDigest.hidden = false;
    if (claim.request) {
      const match = byId("matched-request");
      match.textContent = `${ShopRequest.scopes[claim.scope]} · Request ${claim.request.slice(-8)}`;
      match.hidden = false;
      const printRequest = byId("print-request");
      const requestSource = matchedIncludedRequest ? "Request included in the packet" : "Separate shop request";
      printRequest.textContent = `${requestSource} · Full request ID ${claim.request}`;
      printRequest.hidden = false;
    }
  } catch (error) {
    if (attempt === generation) update(error.message, "bad");
  } finally {
    if (attempt === generation) {
      verifyButton.disabled = false;
      if (moveFocus && [document.body, verifyButton].includes(document.activeElement)) {
        byId("result-heading").focus();
      }
    }
  }
});

resetVerification();

const roadEvidence = byId("road-evidence");
if (roadEvidence) {
  const sample = JSON.parse(roadEvidence.textContent);
  const roadStatus = byId("road-status");
  const roadFindings = byId("road-findings");
  const roadSource = byId("road-source");
  const roadDisclosure = byId("road-disclosure");
  const downloads = byId("road-downloads");
  const idleControl = byId("check-idle");
  const controls = [[idleControl, "idle"], [byId("check-moving"), "moving"], [byId("check-startup"), "startup"]];
  const saveButtons = [byId("save-road-first"), byId("save-road-second")];
  let verifiedPair = null;
  byId("shop-heading").textContent = "Verify a receipt.";
  byId("shop-intro").textContent = "Check the signed QNX example, or verify your own receipt and issuer key.";
  byId("verification-workspace").after(byId("create-request").closest("section"));
  byId("road-example").hidden = false;
  for (const [index, button] of saveButtons.entries()) {
    button.addEventListener("click", () => {
      if (!verifiedPair) return;
      ShopRequest.save(verifiedPair.filenames[index], verifiedPair.files[index]);
    });
  }
  byId("save-road-key").addEventListener("click", () => {
    if (verifiedPair) ShopRequest.save("kit-example-issuer.json", JSON.stringify(verifiedPair.keyFile));
  });
  for (const [selected, mode] of controls) {
    selected.addEventListener("click", async () => {
      for (const [control] of controls) {
        control.disabled = true;
        control.setAttribute("aria-pressed", String(control === selected));
        control.classList.toggle("secondary", control !== selected);
      }
      verifiedPair = null;
      roadFindings.hidden = true;
      roadSource.hidden = true;
      roadDisclosure.hidden = true;
      downloads.hidden = true;
      downloads.open = false;
      roadStatus.className = "status";
      roadStatus.textContent = "Verifying both receipts.";
      try {
        const startup = mode === "startup";
        const keyFile = startup ? sample.startup.issuer : {format: "repair-receipt-issuer/v1", ed25519: sample.issuer.key};
        const packets = startup ? sample.startup.packets : sample.receipts[mode].map(receipt => ({
          format: ShopRequest.packetFormat, request: sample.requests[mode], receipt,
          fingerprint: sample.issuer.fingerprint,
        }));
        if (packets.length !== 2 || packets.some(packet => packet.format !== ShopRequest.packetFormat)) {
          throw new Error("The example needs two verification packets.");
        }
        const verifier = await publicVerifier(new Blob([JSON.stringify(keyFile)]));
        const files = packets.map(packet => JSON.stringify(packet));
        const results = await Promise.all(files.map(async file => {
          const input = new Blob([file]);
          return verifyEvidence(await ShopRequest.readEvidence(input), verifier, null);
        }));
        const [a, b] = results.map(result => result.claim);
        if (startup) {
          if (a.recipe !== ShopRequest.recipe || b.recipe !== ShopRequest.startupRecipe || a.request === b.request ||
              [a, b].some(claim => claim.scope !== "both" || claim.thresholdC !== 95 || claim.source !== "uploaded-csv/v1")) {
            throw new Error("The startup comparison needs both road requests at 95 °C.");
          }
        } else if ([a, b].some(claim => claim.source !== ShopRequest.publishedSource || claim.scope !== mode ||
                                       claim.thresholdC !== 95)) {
          throw new Error("The example receipts must match the selected scope and published recording source.");
        }
        const scope = startup ? "moving" : mode;
        byId("road-first-label").textContent = startup ? "Entire recording" : "KIT drive · 26 July 2017";
        byId("road-second-label").textContent = startup ? "Startup allowance" : "KIT drive · 27 July 2017";
        byId("road-first").textContent = labels.get(a[scope]);
        byId("road-second").textContent = labels.get(b[scope]);
        const [first, second] = packets.map(packet => packet.receipt);
        roadStatus.classList.add("good");
        roadStatus.textContent = startup ? "Both signatures verified." : first === second
          ? `Both signatures verified. The receipts are byte-for-byte identical (${first.length} bytes each).`
          : "Both signatures verified. The receipts differ.";
        roadFindings.hidden = false;
        roadSource.textContent = startup ? "July 27, 2017 · Moving finding · 95 °C"
          : `Signed input type · ${ShopRequest.sourceLabel(a.source)} · 95 °C`;
        roadSource.hidden = false;
        if (mode === "idle" && files[0] === files[1]) {
          byId("road-original-sizes").textContent = sample.originalRoadBytes
            .map(bytes => `${(bytes / 1_000_000).toFixed(2)} MB`).join(" · ");
          byId("road-packet-size").textContent = `${new TextEncoder().encode(files[0]).byteLength} bytes`;
          roadDisclosure.hidden = false;
        }
        const filenames = startup ? ["road-strict-scope.json", "road-startup-scope.json"]
          : [26, 27].map(date => `kit-2017-07-${date}-${scope}-packet.json`);
        verifiedPair = {keyFile, files, filenames};
        saveButtons[0].textContent = startup ? "Save entire-recording packet" : "Save July 26 packet";
        saveButtons[1].textContent = startup ? "Save startup packet" : "Save July 27 packet";
        downloads.hidden = false;
      } catch (error) {
        roadStatus.classList.add("bad");
        roadStatus.textContent = error.message || "Could not verify the sample receipts.";
      } finally {
        for (const [control] of controls) control.disabled = false;
      }
    });
  }
  idleControl.click();
}

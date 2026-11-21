"use strict";

const byId = id => document.getElementById(id);
const issuerFile = byId("trusted-key");
const receiptFile = byId("returned-receipt");
const workOrderDialog = byId("work-order-dialog");
const conditionInput = byId("condition");
const windowInput = byId("recording-window");
const thresholdInput = byId("threshold");
const orderReference = byId("order-reference");
let jobs = new Map();
const time = new Intl.DateTimeFormat(undefined, {dateStyle: "medium", timeStyle: "short"});
const findings = {
  observed: "Threshold observed",
  not_observed: "Threshold not observed",
  insufficient_evidence: "Insufficient evidence",
};
const {conditions} = ShopRequest;
const conditionNotes = {
  idle: "Uses engine-running samples at 0 km/h.",
  moving: "Uses engine-running samples above 0 km/h.",
  both: "Checks 0 km/h and above 0 km/h separately with the engine running.",
};
const repeatInstructions = {
  idle: "Ask for a new recording at idle.",
  moving: "Ask for a new recording while moving.",
  both: "Ask for a new recording that covers idle and moving.",
};
const followUpLabels = {
  idle: "Request idle-only follow-up",
  moving: "Request moving-only follow-up",
  both: "Request follow-up for both conditions",
};
let earlier = null;
let search = null;
let active = null;
let issuer = null;
let keyVersion = 0;
let busy = false;
let matchedReceipt = null;
let pendingCreation = null;

function filingLabel(value) {
  const date = new Date(value);
  return value && Number.isFinite(date.getTime())
    ? `Receipt filed ${time.format(date)}` : "Receipt filing time unavailable";
}

function showRequestRule() {
  byId("condition-note").textContent = conditionNotes[conditionInput.value];
  const value = thresholdInput.valueAsNumber;
  byId("new-rule").textContent = ShopRequest.rule({recipe: windowInput.value,
    thresholdC: ShopRequest.validThreshold(value) ? value : null});
}

conditionInput.addEventListener("change", showRequestRule);
windowInput.addEventListener("change", showRequestRule);
thresholdInput.addEventListener("input", showRequestRule);
showRequestRule();

function status(id, message, error = false) {
  const target = byId(id);
  target.textContent = message;
  target.classList.toggle("bad", error);
}

function current() {
  return jobs.get(active);
}

function updateControls() {
  byId("new-request").disabled = !issuer || busy;
  byId("work-order").disabled = busy;
  conditionInput.disabled = busy;
  windowInput.disabled = busy;
  thresholdInput.disabled = busy;
  issuerFile.disabled = busy;
  const readyToFile = matchedReceipt?.state === "ready";
  byId("filing-actions").hidden = !readyToFile;
  byId("file-receipt").disabled = !readyToFile || busy;
  receiptFile.disabled = busy;
  byId("find-order").disabled = busy;
  byId("clear-search").disabled = busy;
  byId("clear-search").hidden = search === null;
  byId("older-jobs").disabled = busy;
  byId("older-jobs").hidden = earlier === null;
  for (const button of ["new-follow-up", "open-follow-up", "open-original", "view-work-order", "open-replacement"]) {
    byId(button).disabled = busy;
  }
  byId("report-create-follow-up").setAttribute("aria-disabled", String(busy));
  byId("report-replace").setAttribute("aria-disabled", String(busy));
}

function renderJobs() {
  const list = byId("jobs");
  list.replaceChildren();
  for (const job of jobs.values()) {
    if (search !== null && job.workOrder !== search) continue;
    const row = byId("job-row").content.cloneNode(true);
    const button = row.querySelector("button");
    const id = job.request.id;
    row.querySelector(".job-name").textContent = [job.workOrder, job.recheck ? "Recheck" : "",
      ShopRequest.scopes[job.request.scope], id.slice(-8)]
      .filter(Boolean).join(" · ");
    const jobState = row.querySelector(".job-state");
    jobState.textContent = job.receiptInvalid ? "Verification failed"
      : job.supersededBy ? "Withdrawn" : job.acceptedAt ? "Filed" : "Open";
    jobState.classList.toggle("bad", job.receiptInvalid);
    button.dataset.request = id;
    button.setAttribute("aria-pressed", String(id === active));
    list.append(row);
  }
  if (search !== null) {
    status("history-status", list.childElementCount ? `Requests for ${search}` : `No requests for ${search}.`);
  } else {
    status("history-status", jobs.size ? "" : "No requests yet.");
  }
}

function renderConflict(filed, returned) {
  const comparison = byId("receipt-conflict");
  comparison.hidden = !filed || !returned;
  const list = byId("conflict-findings");
  list.replaceChildren();
  if (comparison.hidden) return;
  const rows = Object.entries(conditions)
    .filter(([condition]) => Object.hasOwn(filed, condition))
    .map(([condition, label]) => [label, findings[filed[condition]], findings[returned[condition]]]);
  if (filed.source !== returned.source) {
    rows.push(["Input type", ShopRequest.sourceLabel(filed.source), ShopRequest.sourceLabel(returned.source)]);
  }
  for (const [label, previous, incoming] of rows) {
    const row = byId("conflict-row").content.cloneNode(true);
    row.querySelector("dt").textContent = label;
    row.querySelector(".conflict-filed").textContent = previous;
    row.querySelector(".conflict-returned").textContent = incoming;
    list.append(row);
  }
}

function renderSelection() {
  const job = current();
  byId("selected").hidden = !job;
  if (job) {
    const verified = matchedReceipt?.state === "ready";
    const conflict = matchedReceipt?.state === "conflict";
    const claim = job.claim || (verified ? matchedReceipt.claim : null);
    byId("selected-title").textContent = job.workOrder
      ? `Work order ${job.workOrder}`
      : `Request ${job.request.id.slice(-8)}`;
    const selectedState = byId("selected-state");
    selectedState.textContent = job.receiptInvalid ? "Saved receipt failed verification. Check the original packet or a trusted backup."
      : job.supersededBy ? "Withdrawn from this work order. The original signed files remain available."
      : job.acceptedAt ? filingLabel(job.acceptedAt)
      : `${ShopRequest.scopes[job.request.scope]} · ${verified ? "Ready to file" : "Awaiting a receipt"}`;
    selectedState.classList.toggle("bad", job.receiptInvalid);
    byId("selected-request").textContent = `Request ${job.request.id}`;
    byId("selected-request-fingerprint").textContent = `Request SHA-256 ${job.requestFingerprint}`;
    byId("selected-key").textContent = job.fingerprint ? `Enrolled issuer ${job.fingerprint.match(/.{8}/g).join(" ")}`
      : "The enrolled issuer public key is invalid.";
    byId("selected-rule").textContent = ShopRequest.rule(job.request);
    byId("filed-findings").hidden = !claim || conflict;
    byId("filed-source").hidden = !claim || (conflict && claim.source !== matchedReceipt.claim.source);
    if (claim) byId("filed-source").textContent = "Input · " + ShopRequest.sourceLabel(claim.source);
    byId("save-request").hidden = job.receiptInvalid || !!job.claim || !!job.supersededBy;
    byId("save-packet").hidden = !job.claim;
    byId("view-work-order").hidden = job.receiptInvalid ||
      !(job.claim || job.followUp || job.repeats || job.replacesReview || job.supersededBy);
    byId("open-replacement").hidden = !job.supersededBy;
    byId("individual-files").hidden = !job.claim;
    const missing = job.missingScope;
    byId("follow-up").hidden = !job.claim || !!job.supersededBy;
    byId("follow-up-heading").textContent = missing ? "Follow-up recording" : "Recheck after repair";
    byId("new-follow-up").hidden = !!job.followUp;
    byId("open-follow-up").hidden = !job.followUp;
    byId("new-follow-up").textContent = missing ? "Create follow-up request" : "Create recheck request";
    byId("open-follow-up").textContent = missing ? "Open follow-up request" : "Open recheck request";
    if (missing) {
      byId("follow-up-note").textContent = job.followUp
        ? `The signed finding is on file. Follow-up ${job.followUp.slice(-8)} requests new coverage.`
        : repeatInstructions[missing];
    } else {
      byId("follow-up-note").textContent = job.followUp
        ? "Open the saved recheck to see its conditions and test rule."
        : "Use a fresh recording for the original request’s conditions and test rule.";
    }
    byId("open-original").hidden = !job.repeats;
    if (job.repeats) byId("open-original").textContent =
      `Open ${job.recheck ? "prior" : "original"} request ${job.repeats.slice(-8)}`;
    for (const condition of ["idle", "moving"]) {
      const value = claim?.[condition];
      byId(condition + "-entry").hidden = !value;
      byId(condition + "-value").textContent = findings[value] || "";
    }
  }
  renderConflict(job?.claim, matchedReceipt?.state === "conflict" ? matchedReceipt.claim : null);
  for (const row of byId("jobs").querySelectorAll("button")) {
    row.setAttribute("aria-pressed", String(row.dataset.request === active));
  }
  updateControls();
}

async function api(path, data = null, signal) {
  const options = data ? {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(data),
  } : {cache: "no-store"};
  const response = await fetch(path, {...options, signal});
  const body = await response.json();
  if (!response.ok) {
    const error = new Error(body.message || "The shop register is unavailable.");
    error.status = response.status;
    throw error;
  }
  return body;
}

async function action(statusId, perform) {
  if (busy) return;
  busy = true;
  updateControls();
  try {
    await perform();
  } catch (error) {
    status(statusId, error.message || "Try the action again.", true);
  } finally {
    busy = false;
    updateControls();
  }
}

async function loadJobs({older = false, reference = search} = {}) {
  const before = older ? earlier : null;
  const data = reference === null ? await api(older ? `jobs?before=${before}` : "jobs")
    : await api("lookup", {workOrder: reference, before});
  if (!older) jobs.clear();
  for (const job of data.jobs) jobs.set(job.request.id, job);
  earlier = data.before;
  search = reference;
  renderJobs();
  renderSelection();
}

async function showRecentRequests() {
  try {
    await loadJobs({reference: null});
    orderReference.value = "";
    return true;
  } catch (error) {
    status("history-status", error.message, true);
    return false;
  }
}

issuerFile.addEventListener("change", async () => {
  const version = ++keyVersion;
  issuer = null;
  status("new-status", "");
  updateControls();
  if (!issuerFile.files.length) {
    status("issuer-note", "Use a key whose fingerprint you have confirmed with the issuer.");
    return;
  }
  try {
    const candidate = await ShopRequest.readIssuer(issuerFile.files[0]);
    const digest = await ShopRequest.fingerprint(candidate.key);
    if (version !== keyVersion) return;
    issuer = candidate;
    status("issuer-note", `SHA-256 fingerprint ${digest.match(/.{8}/g).join(" ")}`);
  } catch (error) {
    if (version === keyVersion) status("issuer-note", error.message, true);
  } finally {
    updateControls();
  }
});

function choose(id, receipt = null) {
  active = id;
  matchedReceipt = receipt;
  byId("individual-files").open = false;
  byId("selected-issuer").open = false;
  if (!receipt) receiptFile.value = "";
  status("match-status", "");
  status("file-status", "");
  renderSelection();
}

byId("jobs").addEventListener("click", event => {
  const button = event.target.closest("button[data-request]");
  if (button && !busy) {
    choose(button.dataset.request);
    byId("selected-title").focus();
  }
});
byId("older-jobs").addEventListener("click", () => action("history-status", () => loadJobs({older: true})));
byId("search-orders").addEventListener("submit", event => {
  event.preventDefault();
  action("history-status", async () => {
    const reference = orderReference.value.trim();
    await loadJobs({reference});
    orderReference.value = reference;
    choose(null);
  });
});
byId("clear-search").addEventListener("click", () => action("history-status", async () => {
  if (await showRecentRequests()) {
    choose(null);
    orderReference.focus();
  }
}));
async function showMatchedReceipt(evidence, confirmFiling = false) {
  const {receiptText, packetRequest, fingerprint} = evidence;
  const match = packetRequest ? {receipt: receiptText, request: packetRequest, fingerprint} : {receipt: receiptText};
  const {job, claim, state} = await api("match", match, AbortSignal.timeout(10000));
  if (confirmFiling && state === "alreadyFiled") {
    showFiledReceipt(job, false);
    return state;
  }
  const id = job.request.id;
  if (search !== null && job.workOrder !== search) await showRecentRequests();
  jobs.set(id, job);
  renderJobs();
  choose(id, {evidence, claim, state});
  const message = {
    ready: "Signature verified. Review the matching request below.",
    alreadyFiled: "This exact receipt is already filed.",
    conflict: "A different signed receipt has already been filed for this request.",
  }[state];
  status("match-status", message, state === "conflict");
  const heading = byId(state === "conflict" ? "conflict-heading" : "selected-title");
  heading.focus();
  if (state === "ready" && byId("file-receipt").getBoundingClientRect().bottom > window.innerHeight) {
    heading.scrollIntoView({block: "start"});
  }
  return state;
}

receiptFile.addEventListener("change", () => {
  matchedReceipt = null;
  status("match-status", "");
  status("file-status", "");
  renderSelection();
  if (!receiptFile.files.length) return;
  action("match-status", async () => {
    await showMatchedReceipt(await ShopRequest.readEvidence(receiptFile.files[0]));
  });
});

byId("new-request").addEventListener("click", () => {
  if (!thresholdInput.reportValidity()) return;
  action("new-status", async () => {
    const workOrder = byId("work-order");
    const details = {scope: conditionInput.value, issuer: issuer.text, workOrder: workOrder.value.trim(), recipe: windowInput.value,
      thresholdC: thresholdInput.value === "" ? null : thresholdInput.valueAsNumber};
    const serialized = JSON.stringify(details);
    if (pendingCreation?.details !== serialized) {
      pendingCreation = {details: serialized, id: crypto.randomUUID().replaceAll("-", "")};
    }
    status("new-status", "Creating request.");
    let created;
    try {
      created = await api("jobs", {...details, requestId: pendingCreation.id});
    } catch (error) {
      if (error.status >= 400 && error.status < 500) {
        pendingCreation = null;
        throw error;
      }
      throw new Error("Confirmation was interrupted. Choose Create request again with the same details.");
    }
    pendingCreation = null;
    workOrder.value = "";
    thresholdInput.value = "";
    windowInput.value = ShopRequest.recipe;
    showRequestRule();
    jobs.set(created.request.id, created);
    renderJobs();
    choose(created.request.id);
    status("new-status", "Request created. Download it and send it to the driver.");
    await showRecentRequests();
    byId("selected-title").focus();
  });
});

function saveRequest() {
  const {request} = current();
  ShopRequest.save(`repair-request-${request.id.slice(-8)}.json`, JSON.stringify(request));
}

byId("save-request").addEventListener("click", saveRequest);
byId("save-filed-request").addEventListener("click", saveRequest);

byId("save-packet").addEventListener("click", () => action("file-status", async () => {
  const {job, receipt} = await api(`files/${active}`);
  if (!receipt) throw new Error("File a signed receipt before exporting a verification packet.");
  const {request, fingerprint} = job;
  const packet = {format: ShopRequest.packetFormat, request, receipt, fingerprint};
  ShopRequest.save(`repair-verification-${request.id.slice(-8)}.json`, JSON.stringify(packet));
}));

async function createRepeat(parentId, recheck, fromReport = false) {
  const child = await api(recheck ? "recheck" : "follow-up", {request: parentId});
  if (fromReport) {
    if (!workOrderDialog.open) return;
    workOrderDialog.close();
  }
  const childId = child.request.id;
  const parent = jobs.get(parentId);
  if (parent) jobs.set(parentId, {...parent, followUp: childId});
  jobs.delete(childId);
  jobs = new Map([[childId, child], ...jobs]);
  renderJobs();
  choose(childId);
  const label = recheck ? "Recheck" : "Follow-up";
  status("file-status", child.claim ? `This ${label.toLowerCase()} already has a filed receipt.`
    : `${label} ready. Download the new request and send it to the driver.`);
  byId(child.claim ? "selected-title" : "save-request").focus();
}

byId("new-follow-up").addEventListener("click", () => action("file-status", () => {
  const parent = current();
  return createRepeat(parent.request.id, !parent.missingScope);
}));

async function openJob(id, fromReport = false) {
  const {job} = await api(`files/${id}`);
  if (fromReport) {
    if (!workOrderDialog.open) return;
    workOrderDialog.close();
  }
  jobs.set(id, job);
  choose(id);
  byId("selected-title").focus();
}

for (const [button, field] of [["open-follow-up", "followUp"], ["open-original", "repeats"],
  ["open-replacement", "supersededBy"]]) {
  byId(button).addEventListener("click", () => action("file-status", () => openJob(current()[field])));
}

function reportReading(evidence, label) {
  const row = byId("report-reading").content.cloneNode(true);
  if (label) {
    const title = row.querySelector("h4");
    title.hidden = false;
    title.textContent = label;
  }
  row.querySelector(".report-outcome").textContent = evidence ? findings[evidence.finding] : "Awaiting a receipt";
  if (evidence) {
    for (const [selector, text] of [
      [".report-source", `Source · ${ShopRequest.sourceLabel(evidence.source)}`],
      [".report-filing", filingLabel(evidence.filedAt)],
      [".report-request", `Receipt request ID ${evidence.request}`],
      [".report-digest", `Receipt SHA-256 ${evidence.receiptSha256}`],
      [".report-receipt", `Open receipt ${evidence.request.slice(-8)}`],
    ]) {
      const field = row.querySelector(selector);
      field.hidden = false;
      field.textContent = text;
    }
    row.querySelector(".report-receipt").dataset.request = evidence.request;
  }
  return row;
}

function compareReadings(baseline, recheck) {
  if (recheck.finding === "insufficient_evidence") return "Recheck coverage is insufficient for a comparison.";
  if (!baseline.source || !recheck.source) return "A recording source is unspecified. Review the findings separately.";
  if (baseline.source !== recheck.source) return "The receipts report different input types. Review the findings separately.";
  const before = baseline.finding === "observed";
  const after = recheck.finding === "observed";
  if (before && after) return "Both receipts report that the test rule was met.";
  if (before) return "Only the prior receipt reports that the test rule was met.";
  if (after) return "Only the recheck receipt reports that the test rule was met.";
  return "Both receipts report that the test rule was not met.";
}

function showEarlierReceipts(receipts) {
  const history = byId("report-history");
  const list = byId("report-history-list");
  history.open = false;
  history.hidden = !receipts.length;
  byId("report-history-summary").textContent = `Earlier receipts (${receipts.length})`;
  list.replaceChildren();
  for (const {request, filedAt, findings: signedFindings} of receipts) {
    const row = byId("report-history-entry").content.cloneNode(true);
    row.querySelector(".history-findings").textContent = Object.entries(signedFindings)
      .map(([condition, outcome]) => `${conditions[condition]} · ${findings[outcome]}`).join(" / ");
    row.querySelector(".history-filed").textContent = filingLabel(filedAt);
    const button = row.querySelector("button");
    button.textContent = `Open receipt ${request.slice(-8)}`;
    button.dataset.request = request;
    list.append(row);
  }
}

function showWorkOrder(report) {
  const withdrawn = !!report.supersededBy;
  const hasFindings = report.contexts.some(context => context.evidence || context.baseline);
  byId("report-withdrawn").hidden = !withdrawn;
  for (const [id, request] of [["report-open-replacement", report.supersededBy],
    ["report-open-withdrawn", report.replacesReview]]) {
    const button = byId(id);
    button.hidden = !request;
    button.dataset.request = request ?? "";
  }
  const correction = byId("report-correction");
  correction.open = false;
  correction.hidden = withdrawn || !hasFindings;
  status("report-correction-status", "");
  byId("report-correction-scope").textContent = "Withdraw the findings from this review and issue a fresh request " +
    `(${ShopRequest.scopes[report.scope].toLowerCase()}). The register keeps the signed files for reference.`;
  byId("report-replace").dataset.original = report.originalRequest;
  const pending = report.pending;
  const followUp = report.nextFollowUp;
  const createFollowUp = byId("report-create-follow-up");
  createFollowUp.hidden = !followUp;
  createFollowUp.textContent = followUp ? followUpLabels[followUp.scope] : "";
  createFollowUp.dataset.parent = followUp?.request ?? "";
  byId("report-pending").hidden = !pending;
  if (pending) {
    const label = {original: "Request", "follow-up": "Follow-up", recheck: "Recheck"}[pending.purpose];
    byId("report-pending-summary").textContent = `${label} awaiting a receipt · ${ShopRequest.scopes[pending.scope]} · ` +
      `Request ${pending.request.slice(-8)}`;
    byId("report-pending-print").textContent = `Pending request ID ${pending.request}`;
    byId("report-open-pending").dataset.request = pending.request;
  }
  status("report-open-status", "");
  byId("report-reference").textContent = report.workOrder
    ? `Work order ${report.workOrder}` : `Original request ${report.originalRequest.slice(-8)}`;
  const isRecheck = report.contexts.some(context => context.baseline);
  const summary = withdrawn || isRecheck ? "" : ShopRequest.intakeSummary(report.contexts);
  byId("report-intake").hidden = !summary;
  byId("report-intake-summary").textContent = summary;
  byId("report-recheck-note").hidden = withdrawn || !isRecheck;
  const latest = report.contexts.map(context => context.evidence?.request);
  const receiptSummary = byId("report-receipt-summary");
  receiptSummary.hidden = latest.length !== 2 || !latest.every(Boolean);
  receiptSummary.textContent = receiptSummary.hidden ? "" : latest[0] === latest[1]
    ? "The latest idle and moving findings share one signed receipt."
    : "The latest idle and moving findings come from separate signed receipts.";
  const entries = byId("report-findings");
  entries.replaceChildren();
  const evidenceLink = byId("download-work-evidence");
  evidenceLink.hidden = withdrawn || !hasFindings;
  evidenceLink.href = `work-order/${report.originalRequest}/evidence`;
  byId("report-issuer").textContent = `Enrolled issuer SHA-256 ${report.fingerprint}`;
  for (const {condition, evidence, baseline} of report.contexts) {
    const row = byId("report-condition").content.cloneNode(true);
    row.querySelector("h3").textContent = conditions[condition];
    if (baseline && evidence) {
      const comparison = row.querySelector(".report-comparison");
      comparison.textContent = compareReadings(baseline, evidence);
      comparison.hidden = false;
    }
    const reading = baseline ?? evidence;
    if (reading) {
      const rule = row.querySelector(".report-rule");
      rule.textContent = ShopRequest.rule(reading);
      rule.hidden = false;
    }
    const readings = row.querySelector(".report-readings");
    if (baseline) readings.append(reportReading(baseline, "Prior receipt"));
    readings.append(reportReading(evidence, baseline ? "Recheck" : ""));
    entries.append(row);
  }
  showEarlierReceipts(report.earlierReceipts);
  workOrderDialog.showModal();
}

byId("view-work-order").addEventListener("click", () => action("file-status", async () => {
  showWorkOrder(await api(`work-order/${active}`));
}));
byId("report-create-follow-up").addEventListener("click", event => action("report-open-status", async () => {
  status("report-open-status", "");
  try {
    await createRepeat(event.currentTarget.dataset.parent, false, true);
  } catch (error) {
    if (error.status) throw error;
    throw new Error("Could not confirm the follow-up. Try again.");
  }
}));
byId("report-replace").addEventListener("click", event => action("report-correction-status", async () => {
  status("report-correction-status", "");
  const request = event.currentTarget.dataset.original;
  let replacement;
  try {
    replacement = await api("replace-review", {request}, AbortSignal.timeout(10000));
    if (!workOrderDialog.open) return;
    await loadJobs();
  } catch (error) {
    if (error.status) throw error;
    throw new Error("Could not confirm the replacement. Try again.");
  }
  if (!workOrderDialog.open) return;
  workOrderDialog.close();
  jobs.set(replacement.request.id, replacement);
  renderJobs();
  choose(replacement.request.id);
  status("file-status", replacement.claim ? "This replacement already has a filed receipt."
    : "Replacement ready. Download the new request for the correct recording.");
  byId(replacement.claim || replacement.supersededBy ? "selected-title" : "save-request").focus();
}));
function dismissWorkOrder(event) {
  event.preventDefault();
  workOrderDialog.close();
  byId("view-work-order").focus();
}
byId("close-work-order").addEventListener("click", dismissWorkOrder);
workOrderDialog.addEventListener("cancel", dismissWorkOrder);
byId("print-work-order").addEventListener("click", () => window.print());
workOrderDialog.addEventListener("click", event => {
  const button = event.target.closest("button[data-request]");
  if (button) {
    action("report-open-status", async () => {
      status("report-open-status", "");
      try {
        await openJob(button.dataset.request, true);
      } catch (error) {
        if (error.status) throw error;
        throw new Error("Could not open the request. Try again.");
      }
    });
  }
});

for (const [button, field, filename] of [
  ["save-original", "receipt", "repair-receipt.json"],
  ["save-pin", "issuer", "repair-receipt-issuer.json"],
]) {
  byId(button).addEventListener("click", () => action("file-status", async () => {
    const files = await api(`files/${active}`);
    if (files[field]) ShopRequest.save(filename, files[field]);
  }));
}

function showFiledReceipt(job, alreadyFiled) {
  jobs.set(job.request.id, job);
  matchedReceipt = null;
  receiptFile.value = "";
  status("match-status", "");
  renderJobs();
  renderSelection();
  status("file-status", alreadyFiled ? "This exact receipt is already filed." : "Signature verified and receipt filed.");
  byId("selected-title").focus();
}

byId("file-receipt").addEventListener("click", () => action("file-status", async () => {
  if (matchedReceipt?.state !== "ready") return;
  const {evidence} = matchedReceipt;
  status("file-status", "Filing receipt.");
  let filed;
  try {
    filed = await api("file", {request: active, receipt: evidence.receiptText}, AbortSignal.timeout(10000));
  } catch (error) {
    if (error.status === 409) {
      matchedReceipt = null;
      status("match-status", "");
      renderSelection();
      await showMatchedReceipt(evidence);
      return;
    }
    if (error.status && error.status < 500) throw error;
    let state;
    try {
      state = await showMatchedReceipt(evidence, true);
    } catch {
      // Keep the selected receipt available if the register cannot be reached.
    }
    if (!state || state === "ready") {
      status("file-status", "Could not confirm filing. Choose File verified receipt again.", true);
    }
    return;
  }
  showFiledReceipt(filed.job, filed.alreadyFiled);
}));

action("history-status", loadJobs);

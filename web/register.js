"use strict";

const byId = id => document.getElementById(id);
const issuerFile = byId("trusted-key");
const receiptFile = byId("returned-receipt");
const workOrderDialog = byId("work-order-dialog");
const thresholdInput = byId("threshold");
const orderReference = byId("order-reference");
const jobs = new Map();
const time = new Intl.DateTimeFormat(undefined, {dateStyle: "medium", timeStyle: "short"});
const findings = {
  observed: "Threshold observed",
  not_observed: "Threshold not observed",
  insufficient_evidence: "Insufficient evidence",
};
const conditions = {idle: "At idle", moving: "While moving"};
const repeatInstructions = {
  idle: "Ask for a new recording at idle.",
  moving: "Ask for a new recording while moving.",
  both: "Ask for a new recording that covers idle and moving.",
};
let earlier = null;
let search = null;
let active = null;
let issuer = null;
let keyVersion = 0;
let busy = false;
let matchedReceipt = null;
function showRequestRule() {
  const value = thresholdInput.valueAsNumber;
  byId("new-rule").textContent = ShopRequest.rule({recipe: ShopRequest.recipe,
    thresholdC: ShopRequest.validThreshold(value) ? value : null});
}

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
  thresholdInput.disabled = busy;
  const readyToFile = matchedReceipt?.state === "ready";
  byId("filing-actions").hidden = !readyToFile;
  byId("file-receipt").disabled = !readyToFile || busy;
  receiptFile.disabled = busy;
  byId("find-order").disabled = busy;
  byId("clear-search").disabled = busy;
  byId("clear-search").hidden = search === null;
  byId("older-jobs").disabled = busy;
  byId("older-jobs").hidden = earlier === null;
  for (const button of ["new-follow-up", "open-follow-up", "open-original", "view-work-order"]) {
    byId(button).disabled = busy;
  }
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
    row.querySelector(".job-state").textContent = job.acceptedAt ? "Filed" : "Open";
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
    byId("selected-state").textContent = job.acceptedAt
      ? `Filed ${time.format(new Date(job.acceptedAt))}`
      : `${ShopRequest.scopes[job.request.scope]} · ${verified ? "Ready to file" : "Awaiting a receipt"}`;
    byId("selected-request").textContent = `Request ${job.request.id}`;
    byId("selected-key").textContent = `Enrolled issuer ${job.fingerprint.match(/.{8}/g).join(" ")}`;
    byId("selected-rule").textContent = ShopRequest.rule(job.request);
    byId("filed-findings").hidden = !claim || conflict;
    byId("filed-source").hidden = !claim || (conflict && claim.source !== matchedReceipt.claim.source);
    if (claim) byId("filed-source").textContent = "Input · " + ShopRequest.sourceLabel(claim.source);
    byId("save-request").hidden = !!job.claim;
    byId("save-packet").hidden = !job.claim;
    byId("view-work-order").hidden = !job.claim && !job.followUp && !job.repeats;
    byId("individual-files").hidden = !job.claim;
    const missing = job.missingScope;
    byId("follow-up").hidden = !job.claim;
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

async function api(path, data = null) {
  const options = data ? {
    method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(data),
  } : {cache: "no-store"};
  const response = await fetch(path, options);
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
async function showMatchedReceipt(evidence) {
  const {receiptText, packetRequest, fingerprint} = evidence;
  const match = packetRequest ? {receipt: receiptText, request: packetRequest, fingerprint} : {receipt: receiptText};
  const {job, claim, state} = await api("match", match);
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
    const created = await api("jobs", {scope: byId("condition").value, issuer: issuer.text,
      workOrder: workOrder.value.trim(), thresholdC: thresholdInput.value === "" ? null : thresholdInput.valueAsNumber});
    workOrder.value = "";
    thresholdInput.value = "";
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

byId("new-follow-up").addEventListener("click", () => action("file-status", async () => {
  const recheck = !current().missingScope;
  const child = await api(recheck ? "recheck" : "follow-up", {request: active});
  await loadJobs();
  jobs.set(child.request.id, child);
  choose(child.request.id);
  status("file-status", `${recheck ? "Recheck" : "Follow-up"} ready. Download the new request and send it to the driver.`);
  byId("save-request").focus();
}));

async function openJob(id) {
  const {job} = await api(`files/${id}`);
  jobs.set(id, job);
  choose(id);
  byId("selected-title").focus();
}

for (const [button, field] of [["open-follow-up", "followUp"], ["open-original", "repeats"]]) {
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
      [".report-filing", `Receipt filed ${time.format(new Date(evidence.filedAt))}`],
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

function showWorkOrder(report) {
  byId("report-reference").textContent = report.workOrder
    ? `Work order ${report.workOrder}` : `Original request ${report.originalRequest.slice(-8)}`;
  const latest = report.contexts.map(context => context.evidence?.request);
  const receiptSummary = byId("report-receipt-summary");
  receiptSummary.hidden = latest.length !== 2 || !latest.every(Boolean);
  receiptSummary.textContent = receiptSummary.hidden ? "" : latest[0] === latest[1]
    ? "The latest idle and moving findings share one signed receipt."
    : "The latest idle and moving findings come from separate signed receipts.";
  byId("report-recheck-note").hidden = !report.contexts.some(context => context.baseline);
  const entries = byId("report-findings");
  entries.replaceChildren();
  const evidenceLink = byId("download-work-evidence");
  evidenceLink.hidden = !report.contexts.some(context => context.evidence || context.baseline);
  evidenceLink.href = `work-order/${report.originalRequest}/evidence`;
  byId("report-issuer").textContent = `Enrolled issuer SHA-256 ${report.fingerprint}`;
  for (const {condition, evidence, pendingRequest, baseline} of report.contexts) {
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
    if (pendingRequest && evidence) {
      const pending = row.querySelector(".report-pending");
      pending.hidden = false;
      pending.textContent = `Follow-up ${pendingRequest.slice(-8)} is awaiting a receipt.`;
    }
    entries.append(row);
  }
  workOrderDialog.showModal();
}

byId("view-work-order").addEventListener("click", () => action("file-status", async () => {
  showWorkOrder(await api(`work-order/${active}`));
}));
byId("close-work-order").addEventListener("click", () => workOrderDialog.close());
byId("print-work-order").addEventListener("click", () => window.print());
byId("report-findings").addEventListener("click", event => {
  const button = event.target.closest("button[data-request]");
  if (button) {
    workOrderDialog.close();
    action("file-status", () => openJob(button.dataset.request));
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

byId("file-receipt").addEventListener("click", () => action("file-status", async () => {
  if (matchedReceipt?.state !== "ready") return;
  const {evidence} = matchedReceipt;
  const receipt = evidence.receiptText;
  try {
    const {job, alreadyFiled} = await api("file", {request: active, receipt});
    jobs.set(active, job);
    matchedReceipt = null;
    receiptFile.value = "";
    status("match-status", "");
    renderJobs();
    renderSelection();
    status("file-status", alreadyFiled ? "This exact receipt is already filed." : "Signature verified and receipt filed.");
    byId("selected-title").focus();
  } catch (error) {
    if (error.status === 409) {
      matchedReceipt = null;
      status("match-status", "");
      renderSelection();
      await showMatchedReceipt(evidence);
      return;
    }
    throw error;
  }
}));

action("history-status", loadJobs);

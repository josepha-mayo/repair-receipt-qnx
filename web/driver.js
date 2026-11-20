"use strict";

const byId = id => document.getElementById(id);
const file = byId("file");
const requestFile = byId("shop-request");
const status = byId("status");
const receiptHeading = byId("receipt-heading");
const busyStages = new Set(["booting", "review", "finishing"]);
const driverSession = openDriverSession();
const labels = {
  observed: "Threshold observed",
  not_observed: "Threshold not observed",
  insufficient_evidence: "Insufficient evidence",
};
const coverageGuidance = {
  1: "There are gaps in the recording. Choose a complete recording for this condition.",
  2: "There is too little continuous coverage. Choose a recording with more time in this condition.",
  3: "There are gaps and too little continuous coverage. Choose a complete recording with more time in this condition.",
};
let state = {stage: "ready"};
let changing = false;
let reconnecting = false;
let unconfirmedAction = null;
let actionError = "";
let nextRefresh;
let stateRead = 0;
let requestRead = 0;
let ticket = null;
let loadingRequest = false;
let requestError = "";
let newSelection = false;
let enrollment = null;
let clockBreaks = 0;
let submittedRequest;
let recordingCleared = false;

function openDriverSession() {
  const key = `repair-receipt-session:${location.pathname}`;
  const generated = crypto.randomUUID().replaceAll("-", "");
  try {
    const saved = sessionStorage.getItem(key);
    if (/^[a-f0-9]{32}$/.test(saved)) return saved;
    sessionStorage.setItem(key, generated);
  } catch {
    // The current page can still complete its review if tab storage is unavailable.
  }
  return generated;
}

function keepPolling() {
  return busyStages.has(state.stage) || state.stage === "occupied" || state.template === "building";
}

function showCoverage(claim, coverage) {
  const details = byId("coverage-help");
  const hasClockWarning = !!claim && !!clockBreaks;
  byId("recording-coverage").hidden = !hasClockWarning;
  let visible = hasClockWarning;
  for (const [context, label] of [["idle", "At idle"], ["moving", "While moving"]]) {
    const field = byId(context + "-guidance");
    const guidance = claim?.[context] === "insufficient_evidence" && coverageGuidance[coverage?.[context]];
    field.hidden = !guidance;
    if (guidance) {
      field.textContent = `${label} · ${guidance}`;
      visible = true;
    }
  }
  details.hidden = !visible;
  if (!visible) details.open = false;
}

function render() {
  const {stage, message} = state;
  const claim = newSelection ? null : state.claim;
  byId("recipe-rule").textContent = ShopRequest.rule(claim || ticket || undefined);
  const reviewing = busyStages.has(stage);
  const busy = reviewing || stage === "occupied" || changing || reconnecting;
  byId("driver-workspace").classList.toggle("is-reviewing", reviewing);
  byId("recording-panel").hidden = reviewing;
  const blocked = busy || loadingRequest || !!requestError;
  const preparation = byId("guest-preparation");
  preparation.hidden = state.template !== "building" && state.template !== "failed";
  preparation.textContent = state.template === "failed"
    ? "QNX image preparation failed. Check the local console before restarting."
    : "Preparing QNX for this app session.";
  const benchWithoutRequest = byId("sample").value === "obd-bench" && !ticket;
  file.disabled = busy;
  requestFile.disabled = busy;
  byId("clear-request").hidden = !requestFile.files.length;
  byId("clear-request").disabled = busy;
  byId("sample").disabled = busy;
  byId("import").disabled = blocked || !file.files.length;
  byId("sample-run").disabled = blocked || benchWithoutRequest;
  byId("bench-help").hidden = !benchWithoutRequest;
  byId("recording-reselection").hidden = !recordingCleared;
  byId("actions").hidden = stage !== "review" || reconnecting;
  byId("share").disabled = changing;
  byId("decline").disabled = changing;
  byId("findings").hidden = !claim || stage === "error" || stage === "expired";
  showCoverage(byId("findings").hidden ? null : claim, state.coverage);
  byId("exports").hidden = stage !== "shared" || newSelection || reconnecting || changing;
  byId("download-packet").hidden = !state.packet;
  byId("packet-note").hidden = !state.packet;
  byId("download").classList.toggle("secondary", !!state.packet);
  const requestStatus = byId("request-status");
  requestStatus.textContent = requestError || (loadingRequest ? "Reading the request." : ticket
    ? `${ShopRequest.scopes[ticket.scope]} · Request ${ticket.id.slice(-8)}`
    : "Without a shop request, the review covers both conditions.");
  requestStatus.classList.toggle("bad", !!requestError);
  byId("receipt-scope").hidden = !claim?.request || stage === "error" || stage === "expired";
  const captureSource = byId("capture-source");
  captureSource.hidden = !claim?.source || stage === "error" || stage === "expired";
  if (!captureSource.hidden) captureSource.textContent = ShopRequest.sourceLabel(claim.source);
  if (claim) {
    for (const context of ["idle", "moving"]) {
      byId(context + "-row").hidden = !Object.hasOwn(claim, context);
      byId(context).textContent = labels[claim[context]] || "";
    }
    if (claim.request) {
      byId("receipt-scope").textContent = `${ShopRequest.scopes[claim.scope]} · Request ${claim.request.slice(-8)}`;
    }
  }
  const text = {
    ready: "Choose a recording to start.",
    occupied: "Another driver session is reviewing a recording. Return to that session to finish.",
    booting: state.bench ? "Starting QNX and sampling the simulated adapter." :
      "Starting QNX and checking the recording.",
    review: "Review the exact findings before sharing.",
    finishing: "QNX is applying your decision.",
    shared: "QNX signed the approved receipt.",
    declined: "Sharing declined. No receipt was issued.",
    expired: "This review expired. Start a new review to share a receipt.",
    error: message,
  };
  const statusText = reconnecting ? "Lost contact with the local app. Checking the current review."
    : actionError || (newSelection && stage !== "occupied" ? "Start a review for the new selection." : text[stage]);
  if (status.textContent !== statusText) status.textContent = statusText;
  status.className = "status " + (actionError || reconnecting || stage === "error" ? "bad" : stage === "shared" ? "good" : "");
}

function focusReceipt() {
  receiptHeading.focus({preventScroll: true});
  receiptHeading.scrollIntoView({block: "start"});
}

async function refresh() {
  const version = ++stateRead;
  let updated;
  try {
    const response = await fetch("state", {cache: "no-store", headers: {"X-Repair-Session": driverSession},
      signal: AbortSignal.timeout(5000)});
    if (!response.ok) throw new Error();
    updated = await response.json();
  } catch {
    if (version !== stateRead) return;
    reconnecting = true;
    render();
    nextRefresh = setTimeout(refresh, 1600);
    return;
  }
  if (version !== stateRead) return;
  const jobChanged = updated.job !== state.job;
  const stageChanged = updated.stage !== state.stage;
  const resumeReview = reconnecting && updated.stage === "review" && document.activeElement === document.body;
  if (jobChanged || stageChanged) actionError = "";
  if (jobChanged) newSelection = false;
  if (unconfirmedAction && updated.job === unconfirmedAction.job && updated.stage === unconfirmedAction.stage) {
    actionError = unconfirmedAction.message;
  }
  unconfirmedAction = null;
  reconnecting = false;
  state = updated;
  render();
  if ((stageChanged && state.stage !== "ready") || resumeReview) focusReceipt();
  if (keepPolling()) nextRefresh = setTimeout(refresh, 800);
}

async function send(path, body, type) {
  if (changing || reconnecting) return;
  clearTimeout(nextRefresh);
  ++stateRead;
  changing = true;
  actionError = "";
  const starting = path === "import" || path === "sample";
  if (starting) {
    clockBreaks = 0;
    newSelection = state.stage !== "ready";
  }
  render();
  try {
    const headers = {"Content-Type": type, "X-Repair-Session": driverSession};
    if (ticket && starting) headers["X-Repair-Request"] = JSON.stringify(ticket);
    let payload = body;
    if (path === "import") {
      ({payload, clockBreaks} = await ObdCsv.reviewInput(body));
      submittedRequest = JSON.stringify(ticket);
      render();
    }
    try {
      const response = await fetch(path, {method: "POST", headers, body: payload, signal: AbortSignal.timeout(10000)});
      if (!response.ok && response.status !== 409) {
        const failure = await response.json();
        actionError = failure.message || "The local app rejected this action.";
      }
    } catch {
      unconfirmedAction = {
        job: state.job,
        stage: state.stage,
        message: starting ? "A new review could not be confirmed. Try starting it again."
          : "Your decision could not be confirmed. Review the finding and choose again.",
      };
    }
    await refresh();
  } catch (error) {
    actionError = error.message || "Could not read the selected recording.";
    if (keepPolling()) nextRefresh = setTimeout(refresh, 800);
  } finally {
    changing = false;
    render();
    if (!starting && !reconnecting && state.stage === "review" && document.activeElement === document.body) {
      focusReceipt();
    }
  }
}

function selected() {
  actionError = "";
  newSelection = state.stage !== "ready";
  render();
}

function selectRequest(request) {
  ticket = request;
  if (submittedRequest !== undefined && submittedRequest !== JSON.stringify(request)) {
    file.value = "";
    submittedRequest = undefined;
    clockBreaks = 0;
    recordingCleared = true;
  }
}

file.addEventListener("change", () => {
  submittedRequest = undefined;
  recordingCleared = false;
  clockBreaks = 0;
  selected();
});
byId("sample").addEventListener("change", () => {
  clockBreaks = 0;
  selected();
});
requestFile.addEventListener("change", async () => {
  const version = ++requestRead;
  requestError = "";
  loadingRequest = !!requestFile.files.length;
  if (!loadingRequest) selectRequest(null);
  selected();
  if (!loadingRequest) return;
  try {
    const parsed = await ShopRequest.load(requestFile.files[0]);
    if (version === requestRead) selectRequest(parsed);
  } catch (error) {
    if (version === requestRead) requestError = error.message;
  } finally {
    if (version === requestRead) {
      loadingRequest = false;
      render();
    }
  }
});
byId("clear-request").addEventListener("click", () => {
  requestFile.value = "";
  requestFile.dispatchEvent(new Event("change"));
});
byId("import").addEventListener("click", () => {
  if (file.files.length) send("import", file.files[0], "application/octet-stream");
});
byId("sample-run").addEventListener("click", () => send("sample", byId("sample").value, "text/plain"));
for (const choice of ["share", "decline"]) {
  byId(choice).addEventListener("click", () => send("decision", JSON.stringify({job: state.job, choice}), "application/json"));
}
byId("download").addEventListener("click", () => ShopRequest.save("repair-receipt.json", state.receipt));
byId("download-packet").addEventListener("click", () => {
  const packet = state.packet;
  if (packet && !byId("exports").hidden) {
    ShopRequest.save(`repair-verification-${packet.request.id.slice(-8)}.json`, JSON.stringify(packet));
  }
});
byId("key").addEventListener("click", () => ShopRequest.save("repair-receipt-issuer.json",
  JSON.stringify({format: "repair-receipt-issuer/v1", ed25519: state.issuer})));

async function loadEnrollment() {
  try {
    const response = await fetch("issuer", {cache: "no-store"});
    if (!response.ok) return;
    const profile = await response.json();
    if (!/^[0-9a-f]{64}$/.test(profile.key) || !/^[0-9a-f]{64}$/.test(profile.fingerprint)) return;
    enrollment = profile;
    byId("issuer-policy").textContent = profile.durable
      ? "Confirm this fingerprint with your shop through a trusted channel. Your issuer key is saved for future reviews."
      : "This test issuer is available for the current app session.";
    byId("issuer-fingerprint").textContent = profile.fingerprint.match(/.{8}/g).join(" ");
    byId("issuer-enrollment").hidden = false;
  } catch {
    // Receipt review has its own connection status.
  }
}
byId("key-enroll").addEventListener("click", () => {
  if (enrollment) ShopRequest.save("repair-receipt-issuer.json",
    JSON.stringify({format: "repair-receipt-issuer/v1", ed25519: enrollment.key}));
});

refresh();
loadEnrollment();

"use strict";

const ShopRequest = (() => {
  const legacyRecipe = "coolant-context-demo/v1";
  const recipe = "coolant-duration-demo/v2";
  const startupRecipe = "coolant-startup-window/v3";
  const sustained = "in at least three consecutive samples spanning at least 2 seconds";
  const defaultThreshold = 105;
  const recipes = Object.freeze({
    [legacyRecipe]: "for three consecutive samples",
    [recipe]: sustained,
    [startupRecipe]: sustained,
  });
  const benchSource = "obd-bench/v1";
  const publishedSource = "published-road/v1";
  const uploadedSource = "uploaded-csv/v1";
  const fileSources = Object.freeze({
    [uploadedSource]: "Uploaded CSV",
    "demo-fixture/v1": "Built-in demo recording",
    [publishedSource]: "Published road recording",
  });
  const packetFormat = "repair-receipt-verification/v1";
  const receiptListFormat = "repair-receipt-work-order-list/v1";
  const sha256Hex = /^[a-f0-9]{64}$/;
  const format = "repair-receipt-request/v1";
  const thresholdFormat = "repair-receipt-request/v2";
  const scopes = Object.freeze({idle: "At idle only", moving: "While moving only", both: "At idle and while moving"});
  const conditions = Object.freeze({idle: "At idle", moving: "While moving"});

  function validThreshold(value) {
    return Number.isInteger(value) && value >= -40 && value <= 200;
  }

  function supportsThreshold(selectedRecipe) {
    return selectedRecipe === recipe || selectedRecipe === startupRecipe;
  }

  function rule(request = {recipe}) {
    const check = `${request.thresholdC ?? defaultThreshold} °C or higher ${recipes[request.recipe]}`;
    return request.recipe === startupRecipe
      ? check + ". Allows missing readings before the first complete sample if it arrives within 1 second."
      : check;
  }

  function sourceLabel(source) {
    if (source === benchSource) return "Simulated OBD-II adapter via QNX";
    return Object.hasOwn(fileSources, source) ? fileSources[source] : "Recording source unspecified";
  }

  function intakeSummary(contexts) {
    const filed = contexts.filter(({evidence}) => evidence);
    if (!filed.length) return "";
    const uploaded = filed.filter(({evidence}) => evidence.source === uploadedSource);
    if (!uploaded.length) return "Use a recording from this vehicle to decide which condition to check first.";

    const conditionText = items => items.map(({condition}) => conditions[condition].toLowerCase()).join(" and ");
    const observed = uploaded.filter(({evidence}) => evidence.finding === "observed");
    const belowRule = uploaded.filter(({evidence}) => evidence.finding === "not_observed");
    const incomplete = uploaded.filter(({evidence}) => evidence.finding === "insufficient_evidence");
    const summary = [];
    if (observed.length) {
      const first = observed.length === 1 && contexts.length > 1 ? " first" : "";
      summary.push(`Confirm the data came from this vehicle. Review the complaint ${conditionText(observed)}${first}.`);
    }
    if (belowRule.length) summary.push(`No crossing met the test rule ${conditionText(belowRule)} in the reviewed data.`);
    if (incomplete.length) summary.push(`Coverage was insufficient ${conditionText(incomplete)}.`);
    const other = filed.filter(({evidence}) => evidence.source !== uploadedSource);
    if (other.length) summary.push(`Use a recording from this vehicle to assess the complaint ${conditionText(other)}.`);
    return summary.join(" ");
  }

  function create(scope, threshold = null, selectedRecipe = recipe) {
    if (!Object.hasOwn(scopes, scope)) throw new Error("Choose a supported operating condition.");
    if (!supportsThreshold(selectedRecipe)) throw new Error("Choose a supported recording window.");
    if (threshold !== null && !validThreshold(threshold)) throw new Error("Choose a whole temperature between -40 and 200 °C.");
    const id = Array.from(crypto.getRandomValues(new Uint8Array(16)), byte =>
      byte.toString(16).padStart(2, "0")).join("");
    return threshold === null ? {format, recipe: selectedRecipe, scope, id}
      : {format: thresholdFormat, recipe: selectedRecipe, scope, id, thresholdC: threshold};
  }

  function parse(text) {
    if (text.length > 256) throw new Error("This file exceeds the shop request size limit.");
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new Error("Choose a request file created by Repair Receipt.");
    }
    if (![format, thresholdFormat].includes(value?.format) || typeof value.recipe !== "string" || !Object.hasOwn(recipes, value.recipe) ||
        typeof value.scope !== "string" ||
        !Object.hasOwn(scopes, value.scope) || typeof value.id !== "string" || !/^[0-9a-f]{32}$/.test(value.id)) {
      throw new Error("This request has an unsupported question, scope or format.");
    }
    const expected = {format: value.format, recipe: value.recipe, scope: value.scope, id: value.id};
    if (value.format === thresholdFormat) {
      if (!supportsThreshold(value.recipe) || !validThreshold(value.thresholdC)) {
        throw new Error("The shop request has an invalid temperature threshold.");
      }
      expected.thresholdC = value.thresholdC;
    }
    if (text !== JSON.stringify(expected)) throw new Error("This request has unexpected fields or bytes.");
    return expected;
  }

  async function load(file) {
    if (file.size > 256) throw new Error("This file exceeds the shop request size limit.");
    return parse(await file.text());
  }

  async function readEvidence(file) {
    if (file.size > 4096) throw new Error("This file exceeds the verification packet size limit.");
    const text = await file.text();
    let packet;
    try {
      packet = JSON.parse(text);
    } catch {
      throw new Error("Choose a signed receipt or verification packet in JSON format.");
    }
    if (packet?.format !== packetFormat) {
      if (file.size > 1024) throw new Error("This file exceeds the signed receipt size limit.");
      return {receiptText: text};
    }
    if (Object.keys(packet).length !== 4 || typeof packet.receipt !== "string" || packet.receipt.length > 1024 ||
        typeof packet.fingerprint !== "string" || !/^[a-f0-9]{64}$/.test(packet.fingerprint) ||
        !Object.hasOwn(packet, "request")) {
      throw new Error("The verification packet is invalid.");
    }
    return {receiptText: packet.receipt, packetRequest: parse(JSON.stringify(packet.request)),
      fingerprint: packet.fingerprint};
  }

  async function readReceiptList(file) {
    if (file.size > 512 * 1024) throw new Error("This receipt list exceeds the 512 KiB limit.");
    let value;
    const invalid = "Choose a receipt list saved from the shop work order.";
    try {
      value = JSON.parse(await file.text());
    } catch {
      throw new Error(invalid);
    }
    if (value?.format !== receiptListFormat || Object.keys(value).length !== 3 ||
        typeof value.fingerprint !== "string" || !sha256Hex.test(value.fingerprint) ||
        !Array.isArray(value.receipts) || !value.receipts.length) {
      throw new Error(invalid);
    }
    const receipts = new Map();
    for (const receipt of value.receipts) {
      if (typeof receipt?.request !== "string" || !/^[a-f0-9]{32}$/.test(receipt.request) ||
          typeof receipt.sha256 !== "string" || !sha256Hex.test(receipt.sha256) ||
          Object.keys(receipt).length !== 2 || receipts.has(receipt.request)) {
        throw new Error(invalid);
      }
      receipts.set(receipt.request, receipt.sha256);
    }
    return {fingerprint: value.fingerprint, receipts};
  }

  function hexBytes(hex) {
    return Uint8Array.from(hex.match(/../g), byte => Number.parseInt(byte, 16));
  }

  async function readIssuer(file) {
    if (file.size > 512) throw new Error("The issuer key file exceeds the size limit.");
    const text = await file.text();
    let pin;
    try {
      pin = JSON.parse(text);
    } catch {
      throw new Error("The issuer key file is invalid.");
    }
    if (pin?.format !== "repair-receipt-issuer/v1" ||
        typeof pin.ed25519 !== "string" || !/^[0-9a-f]{64}$/.test(pin.ed25519)) {
      throw new Error("The issuer key file is invalid.");
    }
    return {text, key: hexBytes(pin.ed25519)};
  }

  async function fingerprint(key) {
    const digest = await crypto.subtle.digest("SHA-256", key);
    return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
  }

  function requestFingerprint(request) {
    return fingerprint(new TextEncoder().encode(JSON.stringify(request)));
  }

  function save(name, value) {
    const href = URL.createObjectURL(new Blob([value], {type: "application/json"}));
    const link = document.createElement("a");
    link.href = href;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(href), 1000);
  }

  return Object.freeze({recipe, startupRecipe, legacyRecipe, recipes, benchSource, publishedSource, uploadedSource,
    fileSources, packetFormat, scopes, conditions,
    create, parse, load, rule, sourceLabel, intakeSummary,
    save, validThreshold, supportsThreshold,
    hexBytes, readIssuer, fingerprint, requestFingerprint, readEvidence, readReceiptList});
})();

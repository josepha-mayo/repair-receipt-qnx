"use strict";

const ShopRequest = (() => {
  const legacyRecipe = "coolant-context-demo/v1";
  const recipe = "coolant-duration-demo/v2";
  const defaultThreshold = 105;
  const recipes = Object.freeze({
    [legacyRecipe]: "for three consecutive samples",
    [recipe]: "in at least three consecutive samples spanning at least 2 seconds",
  });
  const benchSource = "obd-bench/v1";
  const publishedSource = "published-road/v1";
  const fileSources = Object.freeze({
    "uploaded-csv/v1": "Uploaded CSV",
    "demo-fixture/v1": "Built-in demo recording",
    [publishedSource]: "Published road recording",
  });
  const packetFormat = "repair-receipt-verification/v1";
  const format = "repair-receipt-request/v1";
  const thresholdFormat = "repair-receipt-request/v2";
  const scopes = Object.freeze({idle: "At idle only", moving: "While moving only", both: "At idle and while moving"});

  function validThreshold(value) {
    return Number.isInteger(value) && value >= -40 && value <= 200;
  }

  function rule(request = {recipe}) {
    return `${request.thresholdC ?? defaultThreshold} °C or higher ${recipes[request.recipe]}`;
  }

  function sourceLabel(source) {
    if (source === benchSource) return "Simulated OBD-II adapter via QNX";
    return Object.hasOwn(fileSources, source) ? fileSources[source] : "Recording source unspecified";
  }

  function create(scope, threshold = null) {
    if (!Object.hasOwn(scopes, scope)) throw new Error("Choose a supported operating condition.");
    if (threshold !== null && !validThreshold(threshold)) throw new Error("Choose a whole temperature between -40 and 200 °C.");
    const id = Array.from(crypto.getRandomValues(new Uint8Array(16)), byte =>
      byte.toString(16).padStart(2, "0")).join("");
    return threshold === null ? {format, recipe, scope, id}
      : {format: thresholdFormat, recipe, scope, id, thresholdC: threshold};
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
      if (value.recipe !== recipe || !validThreshold(value.thresholdC)) {
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

  function save(name, value) {
    const href = URL.createObjectURL(new Blob([value], {type: "application/json"}));
    const link = document.createElement("a");
    link.href = href;
    link.download = name;
    link.click();
    setTimeout(() => URL.revokeObjectURL(href), 1000);
  }

  return Object.freeze({recipe, legacyRecipe, recipes, benchSource, publishedSource, fileSources, packetFormat, scopes,
    create, parse, load, rule, sourceLabel,
    save, validThreshold,
    hexBytes, readIssuer, fingerprint, readEvidence});
})();

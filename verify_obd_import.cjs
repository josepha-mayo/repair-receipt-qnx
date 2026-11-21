"use strict";

const assert = require("node:assert/strict");
const {test} = require("node:test");
const {reviewInput} = require("./web/obd-csv.js");

const header = "Time,Engine RPM [RPM],Vehicle Speed Sensor [km/h],Engine Coolant Temperature [°C]";

function importReadings(readings) {
  const rows = readings.map((fields, second) => `09:00:0${second}.000,${fields}`);
  return reviewInput(new Blob([[header, ...rows].join("\n")]));
}

test("short opening and closing gaps survive projection as missing rows", async () => {
  const sample = "800,0,103";
  const {payload, clockBreaks} = await importReadings([",,", ",0,103", sample, sample, sample, "800,0,"]);
  assert.equal(payload, "5000\n0,,,\n1000,,,\n2000,800,0,103\n3000,800,0,103\n4000,800,0,103\n5000,,,\n");
  assert.equal(clockBreaks, 0);
});

test("a recording with only missing readings is rejected", async () => {
  await assert.rejects(importReadings([",,", "800,,103"]), /no complete RPM, speed and coolant samples/);
});

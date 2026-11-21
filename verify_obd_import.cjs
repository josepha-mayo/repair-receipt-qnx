"use strict";

const assert = require("node:assert/strict");
const {test} = require("node:test");
const {reviewInput} = require("./web/obd-csv.js");

const header = "Time,Engine RPM [RPM],Vehicle Speed Sensor [km/h],Engine Coolant Temperature [°C]";

function importReadings(readings) {
  const rows = readings.map((fields, second) => `09:00:0${second}.000,${fields}`);
  return importRows(rows);
}

function importRows(rows) {
  return reviewInput(new Blob([[header, ...rows].join("\n")]));
}

const torqueHeader = "GPS Time, Device Time,Longitude,Latitude,Engine RPM(rpm),Speed (OBD)(km/h),Engine Coolant Temperature(°C)";
function importTorque(rows, columns = torqueHeader) {
  return reviewInput(new Blob([[columns, ...rows].join("\r\n")]));
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

test("normal midnight rollover keeps chronological samples", async () => {
  const {payload, clockBreaks} = await importRows([
    "23:59:58.000,800,0,106", "23:59:59.000,800,0,106", "00:00:00.000,800,0,106",
  ]);
  assert.equal(payload, "2000\n0,800,0,106\n1000,800,0,106\n2000,800,0,106\n");
  assert.equal(clockBreaks, 0);
});

test("out-of-order samples just across midnight create one coverage gap", async () => {
  const rows = [
    "23:59:57.000,800,0,99", "23:59:58.000,800,0,106", "23:59:59.850,800,0,106",
    "00:00:00.150,800,0,106", "23:59:59.950,800,0,106", "00:00:00.100,800,0,106",
    "00:00:01.000,800,0,106", "00:00:02.000,800,0,106",
  ];
  const {payload, clockBreaks} = await importRows(rows);
  assert.equal(payload, "5000\n0,800,0,99\n1000,800,0,106\n2850,800,0,106\n3150,,,\n4000,800,0,106\n5000,800,0,106\n");
  assert.equal(clockBreaks, 1);
  const daytimeRows = rows.map(row => row.replace(/^23:/, "11:").replace(/^00:/, "12:"));
  assert.deepEqual(await importRows(daytimeRows), {payload, clockBreaks});
});

test("a large rollback and a recording over 24 hours are still rejected", async () => {
  await assert.rejects(importRows(["09:00:00,800,0,106", "09:00:03,800,0,106", "09:00:01.999,800,0,106"]),
    /clock moved backward too far/);
  await assert.rejects(importRows(["18:00:00,800,0,106", "23:59:59,800,0,106", "00:00:00,800,0,106", "18:00:01,800,0,106"]),
    /recording no longer than 24 hours/);
});

test("Torque Pro keeps clock precision and engine state and drops location fields", async () => {
  const {payload, clockBreaks} = await importTorque([
    "-,14-Aug-2021 09:10:00.010,1,2,781.5,0,95",
    "-,14-Aug-2021 09:10:00.260,1,2,0.25,0,95",
    "-,14-Aug-2021 09:10:01.410,1,2,0.0,0,94",
    "-,14-Aug-2021 09:10:02.510,1,2,1000,14,95",
  ]);
  assert.equal(payload, "2500\n0,782,0,95\n250,1,0,95\n1400,0,0,94\n2500,1000,14,95\n");
  assert.equal(clockBreaks, 0);
});

test("Torque Pro keeps missing rows and uses the full date across midnight", async () => {
  const {payload, clockBreaks} = await importTorque([
    "-,29-Feb-2024 23:59:58.000,1,2,-,0,105",
    "-,29-Feb-2024 23:59:59.000,1,2,800,0,105",
    "-,01-Mar-2024 00:00:00.000,1,2,800,-,105",
    "-,01-Mar-2024 00:00:01.000,1,2,800,0,105",
  ]);
  assert.equal(payload, "3000\n0,,,\n1000,800,0,105\n2000,,,\n3000,800,0,105\n");
  assert.equal(clockBreaks, 0);
});

test("Torque Pro rejects shortened or invalid dates and recordings over one day", async () => {
  await assert.rejects(importTorque(["-,15:23.5,1,2,800,0,95"]), /dated Device Time/);
  await assert.rejects(importTorque(["-,29-Feb-2025 09:10:00.000,1,2,800,0,95"]), /invalid Device Time date/);
  await assert.rejects(importTorque([
    "-,14-Aug-2021 09:10:00.000,1,2,800,0,95", "-,15-Aug-2021 09:10:00.001,1,2,800,0,95",
  ]), /recording no longer than 24 hours/);
});

test("Torque Pro requires vehicle speed from the OBD adapter", async () => {
  await assert.rejects(importTorque(["-,14-Aug-2021 09:10:00.000,1,2,800,0,95"],
    torqueHeader.replace("Speed (OBD)(km/h)", "Speed (GPS)(km/h)")), /OBD speed in km\/h/);
});

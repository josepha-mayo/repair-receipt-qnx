const assert = require("node:assert/strict");
const {execFileSync} = require("node:child_process");
const {readFileSync} = require("node:fs");
const path = require("node:path");
const {test} = require("node:test");
const vm = require("node:vm");

const source = path.join(__dirname, "web/work-order-archive.js");
const parser = vm.runInThisContext(readFileSync(source, "utf8") + "\nWorkOrderArchive", {filename: source});
const name = index => `repair-verification-${index.toString(16).padStart(32, "0")}.json`;
const invalid = /Choose an intact work-order ZIP/;
const buildZip = `
import io
import json
import sys
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

output = io.BytesIO()
with ZipFile(output, "w") as archive:
    for name, contents in json.load(sys.stdin):
        archive.writestr(ZipInfo(name), contents.encode("utf-8"), compress_type=ZIP_DEFLATED)
sys.stdout.buffer.write(output.getvalue())
`;

function zip(entries) {
  return execFileSync("python", ["-c", buildZip], {input: JSON.stringify(entries)});
}

function open(bytes, current = () => true) {
  return parser.open(new File([bytes], "work-order.zip"), current);
}

test("returns the complete packet bytes in the same order as the register", async () => {
  const entries = [[name(1), '{"sample":"first"}'], [name(2), '{"sample":"second"}']];
  const bytes = zip(entries);
  const files = await open(bytes);
  assert.deepEqual(files.map(file => file.name), entries.map(([filename]) => filename));
  assert.deepEqual(await Promise.all(files.map(file => file.text())), entries.map(([, contents]) => contents));
  assert.deepEqual(await open(bytes, () => false), []);
});

test("rejects an incomplete archive and an archive with a corrupted checksum", async () => {
  const bytes = zip([[name(1), "{}"]]);
  await assert.rejects(open(bytes.subarray(0, -1)), invalid);
  const wrongCrc = Buffer.from(bytes);
  const centralStart = wrongCrc.readUInt32LE(wrongCrc.length - 6);
  wrongCrc.writeUInt32LE(0, 14);
  wrongCrc.writeUInt32LE(0, centralStart + 16);
  await assert.rejects(open(wrongCrc), invalid);
});

test("bounds packet sizes and accepts the register's flat packet names", async () => {
  assert.equal((await open(zip([[name(1), "x".repeat(4096)]])))[0].size, 4096);
  await assert.rejects(open(zip([[name(1), "x".repeat(4097)]])), invalid);
  await assert.rejects(open(zip([["extra/" + name(1), "{}"]])), invalid);
});

test("directs large histories to the individual packet workflow", async () => {
  const history = Array.from({length: 513}, (_, index) => [name(index), "{}"]);
  await assert.rejects(open(zip(history)), /more than 512 receipts/);
});

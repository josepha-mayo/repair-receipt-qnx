"use strict";

const {openAsBlob} = require("node:fs");
const {writeFile} = require("node:fs/promises");
const {reviewInput} = require("./web/obd-csv.js");

async function main(input, output) {
  const {payload, clockBreaks} = await reviewInput(await openAsBlob(input));
  const contents = typeof payload === "string" ? payload : Buffer.from(await payload.arrayBuffer());
  await writeFile(output, contents, {flag: "wx"});
  console.log(`Saved ${output} with ${clockBreaks} clock breaks.`);
}

if (process.argv.length !== 4) {
  console.error("Usage: node normalize-obd.cjs INPUT.csv OUTPUT.normalized");
  process.exitCode = 2;
} else {
  main(process.argv[2], process.argv[3]).catch(error => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

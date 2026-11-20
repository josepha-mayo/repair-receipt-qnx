"use strict";

const ObdCsv = (() => {
  const normalizedLimit = 4 * 1024 * 1024;
  const exportLimit = 8 * 1024 * 1024;
  const dayMs = 86400000;
  const maxClockRollback = 1000;
  const signals = ["Time", "Engine RPM [RPM]", "Vehicle Speed Sensor [km/h]", "Engine Coolant Temperature [°C]"];

  function fields(line) {
    const values = [];
    const token = /"((?:[^"]|"")*)"|([^",]*)/y;
    let index = 0;
    do {
      token.lastIndex = index;
      const value = token.exec(line);
      if (!value || (token.lastIndex < line.length && line[token.lastIndex] !== ",")) {
        throw new Error("The export contains a malformed CSV row.");
      }
      values.push(value[1] === undefined ? value[2] : value[1].replaceAll('""', '"'));
      index = token.lastIndex + 1;
    } while (index <= line.length);
    return values;
  }

  function clock(value) {
    const parts = /^(\d\d):(\d\d):(\d\d)(?:\.(\d{1,3}))?$/.exec(value);
    if (!parts || +parts[1] > 23 || +parts[2] > 59 || +parts[3] > 59) {
      throw new Error("The export needs a Time column with hours, minutes and seconds.");
    }
    return ((+parts[1] * 60 + +parts[2]) * 60 + +parts[3]) * 1000 + +(parts[4] || "").padEnd(3, "0");
  }

  function sensor(value, minimum, maximum) {
    const number = Number(value);
    if (!/^-?\d+(?:\.0+)?$/.test(value) || number < minimum || number > maximum) {
      throw new Error("Use whole-number RPM, km/h and °C readings within the supported ranges.");
    }
    return number;
  }

  function project(text) {
    const lines = text.split(/\r?\n/);
    const header = fields(lines[0]).map(name => name.trim().replace("Â°", "°"));
    const indices = signals.map(name => header.indexOf(name));
    if (indices.some((index, field) => index === -1 || index !== header.lastIndexOf(signals[field]))) {
      throw new Error("Use a normalized CSV or a metric OBD Auto Doctor export with Time, RPM, vehicle speed and coolant temperature.");
    }
    const rows = [];
    let first;
    let last;
    let offset = 0;
    let completeRows = 0;
    let clockBreaks = 0;
    let inClockBreak = false;
    for (const line of lines.slice(1)) {
      if (!line) continue;
      const row = fields(line);
      if (row.length !== header.length) throw new Error("The export row does not match its header.");
      const [time, rpm, speed, temperature] = indices.map(index => row[index].trim());
      const timeOfDay = clock(time);
      const sample = rpm && speed && temperature
        ? [sensor(rpm, 0, 14000), sensor(speed, 0, 400), sensor(temperature, -40, 200)].join(",")
        : null;
      let current = timeOfDay + offset;
      if (!offset && last >= 64800000 && timeOfDay <= 21600000) {
        offset = dayMs;
        current += offset;
      }
      if (last !== undefined && current <= last) {
        if (last - current > maxClockRollback || current < first) {
          throw new Error("The export clock moved backward too far to recover this recording.");
        }
        const uncertainFrom = current - first;
        const previous = rows.at(-1);
        if (!inClockBreak && current === last && previous?.elapsed === uncertainFrom && previous.sample === sample) {
          continue;
        }
        // Remove the whole overlap before marking the last trusted clock position as a break.
        while (rows.length && rows.at(-1).elapsed >= uncertainFrom) {
          if (rows.pop().sample !== null) --completeRows;
        }
        rows.push({elapsed: last - first, sample: null});
        if (!inClockBreak) ++clockBreaks;
        inClockBreak = true;
        continue;
      }
      inClockBreak = false;
      first ??= current;
      last = current;
      const elapsed = current - first;
      if (elapsed > dayMs) throw new Error("Use a recording no longer than 24 hours.");
      if (sample === null) {
        if (rows.length) rows.push({elapsed, sample: null});
        continue;
      }
      rows.push({elapsed, sample});
      ++completeRows;
    }
    if (!completeRows) throw new Error("The export has no complete RPM, speed and coolant samples.");
    const body = rows.map(({elapsed, sample}) => `${elapsed},${sample ?? ",,"}`).join("\n");
    const payload = `${Math.max(1, last - first)}\n${body}\n`;
    if (payload.length > normalizedLimit) throw new Error("The projected recording exceeds 4 MiB.");
    return {payload, clockBreaks};
  }

  async function reviewInput(file) {
    if (file.size > exportLimit) throw new Error("Choose an OBD Auto Doctor export of at most 8 MiB.");
    const firstLine = (await file.slice(0, 256).text()).split(/\r?\n/, 1)[0];
    if (/^\s*\+?\d+$/.test(firstLine)) {
      if (file.size > normalizedLimit) throw new Error("Choose a normalized recording of at most 4 MiB.");
      return {payload: file, clockBreaks: 0};
    }
    return project(await file.text());
  }

  return Object.freeze({reviewInput});
})();

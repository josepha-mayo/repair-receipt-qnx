"use strict";

// The register writes flat, single-disk ZIPs with DEFLATE and no extra fields.
// APPNOTE 4.3.7, 4.3.12 and 4.3.16 specify the three headers below.
const WorkOrderArchive = (() => {
  const endHeader = 22;
  const centralHeader = 46;
  const localHeader = 30;
  const maxEntries = 512;
  const maxPacketBytes = 4096;
  const maxCompressedBytes = maxPacketBytes + 64;
  const maxArchiveBytes = maxEntries * (maxCompressedBytes + 192) + endHeader;
  const filename = /^repair-verification-[a-f0-9]{32}\.json$/;
  const invalid = "Choose an intact work-order ZIP exported by Repair Receipt.";

  function entries(buffer) {
    const header = new DataView(buffer);
    const word = offset => header.getUint16(offset, true);
    const integer = offset => header.getUint32(offset, true);
    const end = buffer.byteLength - endHeader;
    const decode = new TextDecoder();
    if (end < 0 || integer(end) !== 0x06054b50 || word(end + 4) || word(end + 6) || word(end + 20)) {
      throw new Error(invalid);
    }
    const count = word(end + 10);
    if (count > maxEntries) {
      throw new Error(`Extract the packet files to verify a work order with more than ${maxEntries} receipts.`);
    }
    let central = integer(end + 16);
    const centralStart = central;
    if (!count || word(end + 8) !== count || central + integer(end + 12) !== end) throw new Error(invalid);
    const result = [];
    const names = new Set();
    let local = 0;
    for (let index = 0; index < count; index++) {
      if (central + centralHeader > end || integer(central) !== 0x02014b50 || word(central + 8) ||
          word(central + 10) !== 8 || word(central + 30) || word(central + 32) || word(central + 34) ||
          integer(central + 42) !== local) throw new Error(invalid);
      const crc = integer(central + 16);
      const compressed = integer(central + 20);
      const size = integer(central + 24);
      const nameLength = word(central + 28);
      const nameStart = central + centralHeader;
      if (nameStart + nameLength > end || local + localHeader > centralStart ||
          !compressed || compressed > maxCompressedBytes || !size || size > maxPacketBytes) throw new Error(invalid);
      const name = decode.decode(new Uint8Array(buffer, nameStart, nameLength));
      if (!filename.test(name) || names.has(name)) throw new Error(invalid);
      const localName = local + localHeader;
      const data = localName + nameLength;
      if (data + compressed > centralStart || integer(local) !== 0x04034b50 || word(local + 6) ||
          word(local + 8) !== 8 || integer(local + 14) !== crc || integer(local + 18) !== compressed ||
          integer(local + 22) !== size || word(local + 26) !== nameLength || word(local + 28) ||
          decode.decode(new Uint8Array(buffer, localName, nameLength)) !== name) throw new Error(invalid);
      names.add(name);
      result.push({name, data, compressed, size, crc});
      local = data + compressed;
      central = nameStart + nameLength;
    }
    if (local !== centralStart || central !== end) throw new Error(invalid);
    return result;
  }

  function crc32(bytes) {
    let crc = 0xffffffff;
    for (const byte of bytes) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit++) {
        crc = (crc >>> 1) ^ (-(crc & 1) & 0xedb88320);
      }
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  async function inflate(buffer, entry) {
    const input = new Blob([new Uint8Array(buffer, entry.data, entry.compressed)]);
    let decompressor;
    try {
      decompressor = new DecompressionStream("deflate-raw");
    } catch {
      throw new Error("Use a current Chromium browser to open the ZIP, or extract its packet files and select them.");
    }
    const reader = input.stream().pipeThrough(decompressor).getReader();
    const bytes = new Uint8Array(entry.size);
    let length = 0;
    try {
      while (true) {
        const {done, value} = await reader.read();
        if (done) break;
        if (length + value.byteLength > bytes.length) {
          await reader.cancel();
          throw new Error(invalid);
        }
        bytes.set(value, length);
        length += value.byteLength;
      }
    } catch {
      throw new Error(invalid);
    } finally {
      reader.releaseLock();
    }
    if (length !== bytes.length || crc32(bytes) !== entry.crc) throw new Error(invalid);
    return new File([bytes], entry.name, {type: "application/json"});
  }

  async function open(file, isCurrent) {
    if (file.size > maxArchiveBytes) {
      throw new Error("This work-order ZIP is too large. Extract its packet files and select them.");
    }
    const buffer = await file.arrayBuffer();
    const packetFiles = [];
    for (const entry of entries(buffer)) {
      if (!isCurrent()) return [];
      packetFiles.push(await inflate(buffer, entry));
    }
    return packetFiles;
  }

  return Object.freeze({open});
})();

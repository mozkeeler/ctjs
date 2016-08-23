"use strict";

var fs = require("fs");
var zlib = require("zlib");

var ctjs = require("./ctjs");
var mozillaRoots = require("./mozillaRoots");

if (process.argv.length < 4) {
  console.error(`Usage: ${process.argv[0]} ${process.argv[1]} <go ct db> <index file>`);
  process.exit(1);
}

function readOffset(fd, buf) {
  let bytesRead = fs.readSync(fd, buf, 0, 8, null);
  if (bytesRead != 8) {
    return null;
  }
  let offset = buf.readUIntLE(0, 6);

  return offset;
}

function readIndex(path) {
  return new Promise((resolve, reject) => {
    fs.open(path, "r", (err, fd) => {
      if (err) {
        reject(err);
        return;
      }
      let offsets = [];
      let buf = Buffer.alloc(8);
      while (true) {
        if (offsets.length % 1000000 == 0) {
          console.log(offsets.length);
        }
        let offset = readOffset(fd, buf);
        if (offset == null) {
          break;
        }
        offsets.push(offset);
      }
      resolve(offsets);
    });
  });
}

function bytesToDate(bytes) {
  if (bytes.length != 8) {
    throw new Error(`unexpected input to bytesToDate: ${bytes}`);
  }
  if (bytes[0] != 0 || bytes[1] != 0) {
    throw new Error(`unhandled input to bytesToDate: ${bytes}`);
  }
  let val = 0;
  for (let i = 2; i < bytes.length; i++) {
    val *= 256;
    val += bytes[i];
  }
  return new Date(val);
}

function hexdump(buffer) {
  let hex = buffer.toString("hex");
  let lines = hex.split(/([a-f0-9]{32})/g);
  // lines now consists of alternating empty lines and hex lines
  lines.forEach((line) => {
    if (line.length > 0) {
      console.log(line.replace(/[a-f0-9]{2}/g, "$& "));
    }
  });
}

function readOneEntry(path, entryNumber, offsets) {
  return new Promise((resolve, reject) => {
    fs.open(path, "r", (err, fd) => {
      if (err) {
        reject(err);
        return;
      }
      let buf = Buffer.alloc(4);
      console.log(offsets[entryNumber]);
      let bytesRead = fs.readSync(fd, buf, 0, 4, offsets[entryNumber]);
      if (bytesRead != 4) {
        reject(new Error(`unexpectedly read ${bytesRead} bytes instead of 4`));
        return;
      }
      let deflatedEntryLength = buf.readUInt32LE(0);
      console.log(deflatedEntryLength);
      let deflatedEntryBuf = Buffer.alloc(deflatedEntryLength);
      bytesRead = fs.readSync(fd, deflatedEntryBuf, 0, deflatedEntryLength, offsets[entryNumber] + 4);
      if (bytesRead != deflatedEntryLength) {
        reject(new Error(`unexpectedly read ${bytesRead} bytes instead of ${deflatedEntryLength}`));
      }
      let entryBuf = zlib.inflateRawSync(deflatedEntryBuf);
      let cursor = 0;
      let leafInputLength = entryBuf.readUInt32LE(cursor);
      cursor += 4;
      let leafInput = entryBuf.slice(cursor, cursor + leafInputLength);
      cursor += leafInputLength;
      let extraDataLength = entryBuf.readUInt32LE(cursor);
      cursor += 4;
      let extraData = entryBuf.slice(cursor, cursor + extraDataLength);
      cursor += extraDataLength;
      console.log(extraDataLength);
      console.log(extraData.length);
      resolve(ctjs.parseEntry(leafInput, extraData));
    });
  });
}

function nameToCA(name) {
  let ca = { organization: "", organizationalUnit: "", commonName: "" };
  name.rdns.forEach((rdn) => {
    rdn.avas.forEach((ava) => {
      switch (ava.type.toString()) {
        case "id-at-organization":
          ca.organization = ava.value.toString();
          break;
        case "id-at-organizationalUnit":
          ca.organizationalUnit = ava.value.toString();
          break;
        case "id-at-commonName":
          ca.commonName = ava.value.toString();
          break;
        default:
          break;
      }
    });
  });
  return ca;
}

function processEntry(entry) {
  hexdump(Buffer.from(entry.extraData.chain[0]._der._bytes));
  let issuer = nameToCA(entry.leafInput.timestampedEntry.signedEntry.tbsCertificate.issuer);
  console.log(issuer);
  if (entry.extraInput) {
    entry.extraInput.chain.forEach((cert) => {
      console.log(nameToCA(cert.tbsCertificate.issuer));
    });
  }
}

readIndex(process.argv[3])
  .then(readOneEntry.bind(null, process.argv[2], 12823250))
  .then(processEntry)
  .catch(console.error);

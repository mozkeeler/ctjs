"use strict";

var fs = require("fs");
var zlib = require("zlib");

if (process.argv.length < 4) {
  console.error(`Usage: ${process.argv[0]} ${process.argv[1]} <go ct db> <index file output>`);
  process.exit(1);
}

class GOCTDBReader {
  constructor(path) {
    this.path = path;
    this.onEntry = null;
  }

  on(type, callback) {
    if (type != "entry") {
      throw new Error(`unhandled event type '${type}'`);
    }
    this.onEntry = callback;
  }

  go() {
    fs.open(this.path, "r", (err, fd) => {
      if (err) {
        throw err;
      }
      this._readNextEntry(fd, 0, 0);
    });
  }

  _readNextEntry(fd, entryNumber, offset) {
    let self = this;
    let buf = Buffer.alloc(4);
    fs.read(fd, buf, 0, 4, null, (err, bytesRead) => {
      if (bytesRead != 4) {
        throw new Error(`unexpectedly read ${bytesRead} bytes instead of 4`);
      }
      let deflatedEntryLength = buf.readUInt32LE(0);
      let deflatedEntryBuf = Buffer.alloc(deflatedEntryLength);
      fs.read(fd, deflatedEntryBuf, 0, deflatedEntryLength, null,
              (err, bytesRead) => {
        if (bytesRead != deflatedEntryLength) {
          throw new Error(`unexpectedly read ${bytesRead} bytes instead of ${deflatedEntryLength}`);
        }
        let entryBuf = zlib.inflateRawSync(deflatedEntryBuf);
        let leafInputLength = entryBuf.readUInt32LE(0);
        let leafInput = entryBuf.slice(4, leafInputLength);
        // [1 byte version] [1 byte type] [8 bytes timestamp]
        let timestamp = leafInput.slice(2, 10);
        self.onEntry({ entryNumber, offset, timestamp });
        self._readNextEntry(fd, entryNumber + 1, offset + 4 + deflatedEntryLength);
      });
    });
  }
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

function saveEntry(fd, entry) {
  /*
  let entryNumberBuf = Buffer.alloc(8);
  entryNumberBuf.writeUInt32LE(entry.entryNumber, 0);
  let bytesWritten = fs.writeSync(fd, entryNumberBuf, 0, 8);
  if (bytesWritten != 8) {
    console.error(`unexpectedly wrote ${bytesWritten} instead of 8`);
  }
  */
  let offsetBuf = Buffer.alloc(8);
  offsetBuf.writeUIntLE(entry.offset, 0, 6);
  let bytesWritten = fs.writeSync(fd, offsetBuf, 0, 8);
  if (bytesWritten != 8) {
    console.error(`unexpectedly wrote ${bytesWritten} instead of 8`);
  }
  /*
  bytesWritten = fs.writeSync(fd, entry.timestamp, 0, 8);
  if (bytesWritten != 8) {
    console.error(`unexpectedly wrote ${bytesWritten} instead of 8`);
  }
  */
}

// 12823250: Thu Mar 31 2016 17:00:27 GMT-0700 (PDT)
fs.open(process.argv[3], "w", (err, fd) => {
  if (err) {
    console.error(err);
    return;
  }
  var reader = new GOCTDBReader(process.argv[2]);
  reader.on("entry", (entry) => {
    saveEntry(fd, entry);
  });
  reader.go();
});

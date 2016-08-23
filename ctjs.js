"use strict";

var fs = require("fs");
var https = require("https");
var zlib = require("zlib");

var lintx509 = require("./lintx509").lintx509;

const LOG_DEBUG = 5;
const LOG_ERRORS = 0;
var logLevel = LOG_ERRORS;

function debug(message) {
  if (logLevel >= LOG_DEBUG) {
    console.log(message);
  }
}

function error(message) {
  if (logLevel >= LOG_ERRORS) {
    console.error(message);
  }
}

function hexdump(buffer) {
  let hex = buffer.toString("hex");
  let lines = hex.split(/([a-f0-9]{32})/g);
  // lines now consists of alternating empty lines and hex lines
  lines.forEach((line) => {
    if (line.length > 0) {
      debug(line.replace(/[a-f0-9]{2}/g, "$& "));
    }
  });
}

function bufferToArray(buffer) {
  let arr = [];
  for (let i = 0; i < buffer.length; i++) {
    arr.push(buffer[i]);
  }
  return arr;
}

class BufferReader {
  constructor(buffer) {
    this.buffer = buffer;
    this.cursor = 0;
  }

  readByte() {
    let byte = this.buffer.readUInt8(this.cursor);
    this.cursor++;
    return byte;
  }

  read2ByteLength() {
    let uint16be = this.buffer.readUInt16BE(this.cursor);
    this.cursor += 2;
    return uint16be;
  }

  read3ByteLength() {
    let length = this.buffer.readUIntBE(this.cursor, 3);
    this.cursor += 3;
    return length;
  }

  readBytes(length) {
    let bytes = this.buffer.slice(this.cursor, this.cursor + length);
    this.cursor += length;
    return bytes;
  }

  sliceAtCursor() {
    return this.buffer.slice(this.cursor);
  }

  hasMore() {
    return this.cursor < this.buffer.length;
  }

  remainingBytes() {
    return this.buffer.length - this.cursor;
  }
}

// opaque ASN.1Cert<1..2^24-1>;
function parseX509Entry(x509Entry) {
  let certificate = new lintx509.Certificate(
    new lintx509.DER(bufferToArray(x509Entry)));
  certificate.parse();
  return certificate;
}

// opaque TBSCertificate<1..2^24-1>;
//
// struct {
//   opaque issuer_key_hash[32];
//   TBSCertificate tbs_certificate;
// } PreCert;
function parsePrecertEntry(issuerKeyHash, precertEntryBytes) {
  let tbsCertificate = new lintx509.TBSCertificate(
    new lintx509.DER(bufferToArray(precertEntryBytes)));
  tbsCertificate.parse();
  return { issuerKeyHash, tbsCertificate };
}

// opaque CtExtensions<0..2^16-1>;
function parseCtExtensions(extensions) {
  return extensions;
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

// enum { x509_entry(0), precert_entry(1), (65535) } LogEntryType;
//
// struct {
//     uint64 timestamp;
//     LogEntryType entry_type;
//     select(entry_type) {
//         case x509_entry: ASN.1Cert;
//         case precert_entry: PreCert;
//     } signed_entry;
//     CtExtensions extensions;
// } TimestampedEntry;
const x509_entry = 0;
const precert_entry = 1;

function parseTimestampedEntry(timestampedEntry) {
  let reader = new BufferReader(timestampedEntry);
  let timestamp = bytesToDate(reader.readBytes(8));
  let entryType = reader.read2ByteLength();
  let signedEntry = null;
  let mark;
  switch(entryType) {
    case x509_entry:
      let x509EntryLength = reader.read3ByteLength();
      signedEntry = parseX509Entry(reader.readBytes(x509EntryLength));
      break;
    case precert_entry:
      let issuerKeyHash = reader.readBytes(32);
      let precertEntryLength = reader.read3ByteLength();
      let precertEntryBytes = reader.readBytes(precertEntryLength);
      signedEntry = parsePrecertEntry(issuerKeyHash, precertEntryBytes);
      break;
    default: throw new Error(`unknown LogEntryType ${entryType}`);
  }
  let extensions = null;
  if (reader.hasMore()) {
    let extensionsLength = reader.read2ByteLength();
    extensions = parseCtExtensions(reader.readBytes(extensionsLength));
  }
  return {
    timestamp,
    entryType,
    signedEntry,
    extensions
  };
}

// enum { v1(0), (255) }
//   Version;
//
// enum { timestamped_entry(0), (255) }
//   MerkleLeafType;
//
// struct {
//     Version version;
//     MerkleLeafType leaf_type;
//     select (leaf_type) {
//         case timestamped_entry: TimestampedEntry;
//     }
// } MerkleTreeLeaf;
function parseMerkleTreeLeaf(merkleTreeLeaf) {
  let reader = new BufferReader(merkleTreeLeaf);
  let version = reader.readByte();
  let leafType = reader.readByte();
  let timestampedEntry = parseTimestampedEntry(reader.sliceAtCursor());
  return { version,
           leafType,
           timestampedEntry };
}

// TODO: make this configurable/whatever
//const cacheDirectory = "/var/run/media/keeler/579f28b5-5168-481b-acfc-6b47f55b1f2d/ct/cache";
const cacheDirectory = "/home/keeler/src/ctjs/tmp/";

function getRawEntries(logName, firstEntry, numEntries) {
  return getEntriesFromServer(logName, firstEntry, numEntries);
  /*
  return new Promise((resolve, reject) => {
    let cacheFilename = `${cacheDirectory}/${logName.replace("/", "%")}:${entryNumber}.gz`;
    fs.access(cacheFilename, (err) => {
      if (err) {
        getEntryFromServer(logName, entryNumber)
          .then(resolve)
          .catch(reject);
      } else {
        fs.readFile(cacheFilename, (err, gzippedData) => {
          if (err) {
            reject(err);
          } else {
            zlib.gunzip(gzippedData, (err, data) => {
              if (err) {
                reject(err);
              } else {
                debug(`got ${logName}:${entryNumber} from the cache`);
                resolve(JSON.parse(data.toString("utf8")));
              }
            });
          }
        });
      }
    });
  });
  */
}

function cacheEntry(logName, entryNumber, entry) {
  let cacheFilename = `${cacheDirectory}/${logName.replace("/", "%")}:${entryNumber}.gz`;
  let data = JSON.stringify(entry);
  zlib.gzip(data, { level: zlib.Z_BEST_COMPRESSION }, (err, gzippedData) => {
    if (err) {
      error(err);
    } else {
      fs.writeFile(cacheFilename, gzippedData, (err) => {
        if (err) {
          error(err);
        } else {
          debug(`wrote ${cacheFilename}`);
        }
      });
    }
  });
}

function getEntriesFromServer(logName, firstEntry, numEntries) {
  return new Promise((resolve, reject) => {
    let pathPrefix = "";
    let hostname = logName;
    if (logName.includes("/")) {
      pathPrefix = logName.substring(logName.indexOf("/"));
      hostname = logName.substring(0, logName.indexOf("/"));
    }
    let options = {
      hostname: hostname,
      port: 443,
      path: `${pathPrefix}/ct/v1/get-entries?start=${firstEntry}&end=${firstEntry + numEntries}`,
      method: "GET",

    };
    https.get(options, (res) => {
      let buffers = [];
      res.on("data", (data) => {
        buffers.push(data);
      });
      res.on("end", () => {
        debug(`got ${logName}:${firstEntry}-${firstEntry + numEntries} from the server`);
        let json = Buffer.concat(buffers).toString("utf8");
        if (json.error_message) {
          reject(json.error_message);
          return;
        }
        let entries = JSON.parse(json).entries;
        for (let i = 0; i < entries.length; i++) {
          cacheEntry(logName, firstEntry + i, entries[i]);
        }
        resolve(entries);
      });
      res.on("error", (e) => {
        reject(e);
      });
    });
  });
}

// struct {
//		 ASN.1Cert leaf_certificate;
//		 ASN.1Cert certificate_chain<0..2^24-1>;
// } X509ChainEntry;
//
// struct {
//		 ASN.1Cert pre_certificate;
//		 ASN.1Cert precertificate_chain<0..2^24-1>;
// } PrecertChainEntry;
function parseJSONEntry(jsonEntry) {
  let leafInputBuffer = Buffer.from(jsonEntry.leaf_input, "base64");
  let extraDataBuffer = Buffer.from(jsonEntry.extra_data, "base64");
  return parseEntry(leafInputBuffer, extraDataBuffer);
}

function parseEntry(leafInputBuffer, extraDataBuffer) {
  let leafInput = parseMerkleTreeLeaf(leafInputBuffer);
  let extraData = parseExtraData(extraDataBuffer);
  return { leafInput, extraData };
}

function parseExtraData(extraDataBuffer) {
  if (extraDataBuffer.length < 3) {
    return { certificate: null, chain: [] };
  }

  let reader = new BufferReader(extraDataBuffer);
  let certificateLength = reader.read3ByteLength();
  if (certificateLength > reader.remainingBytes()) {
    return { certificate: null, chain: [] }; // TODO: annotate with error?
  }

  let certificate = parseX509Entry(reader.readBytes(certificateLength));
  if (!reader.hasMore()) {
    return { certificate, chain: [] };
  }

  let totalChainLength = reader.read3ByteLength();
  if (totalChainLength != reader.remainingBytes()) {
    return { certificate, chain: [] }; // TODO: annotate with error?
  }
  let chain = [];
  while (reader.hasMore()) {
    let certificateLength = reader.read3ByteLength();
    if (certificateLength > reader.remainingBytes()) {
      return { certificate, chain }; // TODO: annotate with error?
    }
    let certificate = parseX509Entry(reader.readBytes(certificateLength));
    chain.push(certificate);
  }
  return { certificate, chain };
}

function parseEntries(entries) {
  let parsedEntries = [];
  entries.forEach((entry) => {
    parsedEntries.push(parseJSONEntry(entry));
  });
  return parsedEntries;
}

function getEntry(entryNumber) {
  return getRawEntries("ct.googleapis.com/aviator", parseInt(entryNumber), 1)
           .then(parseEntries)
           .then((parsedEntries) => {
             return parsedEntries[0];
           });
}

function getEntries(firstEntry, numEntries) {
  if (numEntries > 100) {
    throw new Error(`too many entries for getEntries (${numEntries})`);
  }
  return getRawEntries("ct.googleapis.com/aviator", parseInt(firstEntry),
                       parseInt(numEntries)).then(parseEntries);
}

exports.getEntry = getEntry;
exports.getEntries = getEntries;
exports.parseEntry = parseEntry;

/*
function getAndProcessEntry(entryNumber) {
  return getRawEntry("ct.googleapis.com/aviator", entryNumber)
    .then(parseJSONEntry)
    .then(processEntry)
    .catch((e) => {
      console.error(e);
      console.error(e.stack);
    });
}

function getAndProcessBatchOfEntries(startEntryNumber) {
  let batchSize = 5;
  let promises = [];
  for (let i = 0; i < batchSize; i++) {
    promises.push(getAndProcessEntry(startEntryNumber - i));
  }
  Promise.all(promises).then((results) => {
    if (!results.includes(false)) {
      scheduleNewBatch(startEntryNumber - batchSize);
    }
  }).catch((e) => {
    error(e);
  });
}

function scheduleNewBatch(startEntryNumber) {
  setTimeout(getAndProcessBatchOfEntries.bind(null, startEntryNumber), 100);
}

function tbsCertHasSubjectAltNameXtn(tbsCert) {
  return tbsCert.extensions.some((extension) => {
    return extension.extnID.toString() == "id-ce-subjectAltName";
  });
}

const cutoffDate = new Date("2016-04-01");

function processEntry(entry) {
  if (entry.leafInput.timestampedEntry.timestamp < cutoffDate) {
    debug("got to April");
    return false;
  }
  // In the case of x509_entry, signedEntry is a lintx509.Certificate.
  // In the case of precert_entry, signedEntry has a property tbsCertificate.
  let tbsCert = entry.leafInput.timestampedEntry.signedEntry.tbsCertificate;
  if (!tbsCertHasSubjectAltNameXtn(tbsCert)) {
    console.log(tbsCert.issuer.toString());
    console.log(tbsCert.subject.toString());
  }
  return true;
}

*/

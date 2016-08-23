"use strict";

var ctjs = require("./ctjs");

if (process.argv.length < 3) {
  console.error(`Usage: ${process.argv[0]} ${process.argv[1]} <entry number>`);
  process.exit(1);
}

/*
ctjs.getEntries(process.argv[2], 10).then((entries) => {
  entries.forEach((entry) => {
    console.log(entry.leafInput.timestampedEntry.timestamp);
    console.log(entry.leafInput.timestampedEntry.signedEntry.tbsCertificate.validity.notBefore.time);
  });
}).catch((e) => {
  console.error(e);
});

function getBatch(startEntryNumber) {
  let stride = 100;
  ctjs.getEntries(startEntryNumber, stride).then((entries) => {
    console.log(`${startEntryNumber} ${entries[0].leafInput.timestampedEntry.timestamp}`);
  }).then(() => {
    setTimeout(getBatch.bind(null, startEntryNumber + stride), 300);
  }).catch((e) => {
    console.error(e);
  });
}

getBatch(parseInt(process.argv[2]));
*/
function dumpEntry(entry) {
  console.log(entry.leafInput.timestampedEntry.signedEntry);
}

ctjs.getEntry(process.argv[2]).then(dumpEntry).catch(console.error);

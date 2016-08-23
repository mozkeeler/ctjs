"use strict";

var zlib = require("zlib");

function doit() {
  while (true) {
    let buf = Buffer.alloc(1024);
    let deflated = zlib.deflateRawSync(buf);
    let inflated = zlib.inflateRawSync(deflated);
  }
}

doit();

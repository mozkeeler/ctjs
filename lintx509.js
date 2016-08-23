"use strict";

const UNIVERSAL = 0 << 6;
const CONSTRUCTED = 1 << 5;
const CONTEXT_SPECIFIC = 2 << 6;

const BOOLEAN = UNIVERSAL | 0x01; // 0x01
const INTEGER = UNIVERSAL | 0x02; // 0x02
const BITSTRING = UNIVERSAL | 0x03; // 0x03
const OCTETSTRING = UNIVERSAL | 0x04; // 0x04
const NULL = UNIVERSAL | 0x05; // 0x05
const OBJECT_IDENTIFIER = UNIVERSAL | 0x06; // 0x06
const UTF8String = UNIVERSAL | 0x0c; // 0x0c
const PrintableString = UNIVERSAL | 0x13; // 0x13
const TeletexString = UNIVERSAL | 0x14; // 0x14
const IA5String = UNIVERSAL | 0x16; // 0x16
const UTCTime = UNIVERSAL | 0x17; // 0x17
const GeneralizedTime = UNIVERSAL | 0x18; // 0x18
const SEQUENCE = UNIVERSAL | CONSTRUCTED | 0x10; // 0x30
const SET = UNIVERSAL | CONSTRUCTED | 0x11; // 0x31

const ERROR_LIBRARY_FAILURE = "error: library failure";
const ERROR_DATA_TRUNCATED = "error: data truncated";
const ERROR_UNEXPECTED_TAG = "error: unexpected tag";
const ERROR_UNSUPPORTED_ASN1 = "error: unsupported asn.1";
const ERROR_INVALID_LENGTH = "error: invalid length";
const ERROR_UNSUPPORTED_LENGTH = "error: unsupported length";
const ERROR_EXTRA_DATA = "error: extra data";
const ERROR_NULL_WITH_DATA = "error: NULL tag containing data";
const ERROR_UNSUPPORTED_X509_FEATURE = "error: unsupported x509 feature";
const ERROR_TIME_NOT_UTCTIME_OR_GENERALIZED_TIME = "error: Time not UTCTime or GeneralizedTime";
const ERROR_TIME_NOT_VALID = "error: Time not valid";
const ERROR_INVALID_BOOLEAN_ENCODING = "error: invalid BOOLEAN encoding";
const ERROR_INVALID_BOOLEAN_VALUE = "error: invalid BOOLEAN value";
const ERROR_UNSUPPORTED_STRING_TYPE = "error: unsupported string type";
const ERROR_UNSUPPORTED_VERSION = "error: unsupported version";
const ERROR_UNSUPPORTED_EXTENSION_VALUE = "error: unsupported extension value";
const ERROR_UNKNOWN_ALGORITHM_IDENTIFIER_PARAMS = "error: unknown algorithm identifier params";
const ERROR_UNSUPPORTED_EC_PUBLIC_KEY = "error: unsupported EC public key";
const ERROR_INVALID_BIT_STRING = "error: invalid BIT STRING encoding";
const ERROR_UNSUPPORTED_IP_ADDRESS = "error: only IPv4 is currently supported";
const ERROR_UNSUPPORTED_GENERAL_NAME_TYPE = "error: unsupported GeneralName type";

const X509v3 = 2;
const EC_UNCOMPRESSED_FORM = 4;

class LintX509Error {
  constructor(message) {
    this._message = message;
  }

  get message() {
    return this._message;
  }
}

class BitString {
  constructor(unusedBits, contents) {
    this._unusedBits = unusedBits;
    this._contents = contents;
  }

  get unusedBits() {
    return this._unusedBits;
  }

  get contents() {
    return this._contents;
  }
}

class DER {
  constructor(bytes) {
    this._bytes = bytes;
    this._cursor = 0;
  }

  readByte() {
    if (this._cursor >= this._bytes.length) {
      throw new LintX509Error(ERROR_DATA_TRUNCATED);
    }
    let val = this._bytes[this._cursor];
    this._cursor++;
    return val;
  }

  getRemainingLength() {
    return this._bytes.length - this._cursor;
  }

  _readExpectedTag(expectedTag) {
    let tag = this.readByte();
    if (tag != expectedTag) {
      throw new LintX509Error(ERROR_UNEXPECTED_TAG);
    }
  }

  _readLength() {
    let nextByte = this.readByte();
    if (nextByte < 0x80) {
      return nextByte;
    }
    if (nextByte == 0x80) {
      throw new LintX509Error(ERROR_UNSUPPORTED_ASN1);
    }
    if (nextByte == 0x81) {
      let length = this.readByte();
      if (length < 0x80) {
        throw new LintX509Error(ERROR_INVALID_LENGTH);
      }
      return length;
    }
    if (nextByte == 0x82) {
      let length1 = this.readByte();
      let length2 = this.readByte();
      let length = (length1 << 8) | length2;
      if (length < 256) {
        throw new LintX509Error(ERROR_INVALID_LENGTH);
      }
      return length;
    }
    throw new LintX509Error(ERROR_UNSUPPORTED_LENGTH);
  }

  readBytes(length) {
    if (this._cursor > this._bytes.length - length) {
      throw new LintX509Error(ERROR_DATA_TRUNCATED);
    }
    let contents = this._bytes.slice(this._cursor, this._cursor + length);
    this._cursor += length;
    return contents;
  }

  readTagAndGetContents(tag) {
    this._readExpectedTag(tag);
    let length = this._readLength();
    let contents = this.readBytes(length);
    return contents;
  }

  _peekByte() {
    if (this._cursor >= this._bytes.length) {
      throw new LintX509Error(ERROR_DATA_TRUNCATED);
    }
    return this._bytes[this._cursor];
  }

  readExpectedTLV(tag) {
    let mark = this._cursor;
    this._readExpectedTag(tag);
    let length = this._readLength();
    // read the bytes so we know they're there (also to advance the cursor)
    this.readBytes(length);
    return new DER(this._bytes.slice(mark, this._cursor));
  }

  readTLV() {
    let nextTag = this._peekByte();
    return this.readExpectedTLV(nextTag);
  }

  readTLVChoice(tagList) {
    let tag = this._peekByte();
    if (!tagList.includes(tag)) {
      throw new LintX509Error(ERROR_UNEXPECTED_TAG);
    }
    return this.readExpectedTLV(tag);
  }

  peekTag(tag) {
    if (this._cursor >= this._bytes.length) {
      return false;
    }
    return this._bytes[this._cursor] == tag;
  }

  assertAtEnd() {
    if (this._cursor != this._bytes.length) {
      throw new LintX509Error(ERROR_EXTRA_DATA);
    }
  }

  atEnd() {
    return this._cursor == this._bytes.length;
  }

  readSEQUENCE() {
    return new DER(this.readTagAndGetContents(SEQUENCE));
  }

  readSET() {
    return new DER(this.readTagAndGetContents(SET));
  }

  readINTEGER() {
    // TODO: validate contents, handle negative values
    // TODO: handle restrictions on values
    return this.readTagAndGetContents(INTEGER);
  }

  readBOOLEAN() {
    let contents = this.readTagAndGetContents(BOOLEAN);
    if (contents.length != 1) {
      throw new LintX509Error(ERROR_INVALID_BOOLEAN_ENCODING);
    }
    if (contents[0] != 0 && contents[0] != 0xff) {
      throw new LintX509Error(ERROR_INVALID_BOOLEAN_VALUE);
    }
    return contents[0];
  }

  readGivenTag(tag) {
    return new DER(this.readTagAndGetContents(tag));
  }

  readBITSTRING() {
    let contents = this.readTagAndGetContents(BITSTRING);
    if (contents.length < 2) {
      throw new LintX509Error(ERROR_UNSUPPORTED_ASN1);
    }
    let unusedBits = contents[0];
    if (unusedBits > 7) {
      throw new LintX509Error(ERROR_INVALID_BIT_STRING);
    }
    return new BitString(unusedBits, contents.slice(1, contents.length));
  }

  readOCTETSTRING() {
    return this.readTagAndGetContents(OCTETSTRING);
  }

  readOID() {
    let contents = this.readTagAndGetContents(OBJECT_IDENTIFIER);
    return new OID(contents);
  }

  readNULL() {
    let contents = this.readTagAndGetContents(NULL);
    if (contents.length != 0) {
      throw new LintX509Error(ERROR_NULL_WITH_DATA);
    }
    return "NULL";
  }

  readContents(tag) {
    return this.readTagAndGetContents(tag);
  }
}

class ASCIIString {
  constructor(bytes) {
    this._asString = "";
    bytes.forEach(b => this._asString += String.fromCharCode(b));
  }

  toString() {
    return this._asString;
  }
}

class OID {
  constructor(bytes) {
  this._values = [];
    // First octet has value 40 * value1 + value2
    // TODO: range checks on the input
    let value1 = Math.floor(bytes[0] / 40);
    let value2 = bytes[0] - 40 * value1;
    this._values.push(value1);
    this._values.push(value2);
    bytes.shift();
    let accumulator = 0;
    // TODO: lots more checks up in here
    while (bytes.length > 0) {
      let value = bytes.shift();
      accumulator *= 128;
      if (value > 128) {
        accumulator += (value - 128);
      } else {
        accumulator += value;
        this._values.push(accumulator);
        accumulator = 0;
      }
    }
  }

  asDottedString() {
    return this._values.join(".");
  }

  toString() {
    let dottedString = this.asDottedString();
    if (dottedString in DottedOIDStringsToDescriptions) {
      return DottedOIDStringsToDescriptions[dottedString];
    }
    return "OID." + dottedString;
  }
}

var DottedOIDStringsToDescriptions = {
  "1.2.840.10045.2.1": "ecPublicKey",
  "1.2.840.10045.3.1.7": "secp256r1",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
  "1.2.840.113549.1.1.1": "rsaEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",

  "1.3.6.1.4.1.11129.2.4.2": "id-embeddedSctList",

  "1.3.6.1.5.5.7.1.1": "id-pe-authorityInfoAccess",
  "1.3.6.1.5.5.7.1.24": "id-pe-tlsfeature",

  "1.3.6.1.5.5.7.3.1": "id-kp-serverAuth",
  "1.3.6.1.5.5.7.3.2": "id-kp-clientAuth",
  "1.3.6.1.5.5.7.3.3": "id-kp-codeSigning",
  "1.3.6.1.5.5.7.3.4": "id-kp-emailProtection",
  "1.3.6.1.5.5.7.3.8": "id-kp-timeStamping",
  "1.3.6.1.5.5.7.3.9": "id-kp-OCSPSigning",

  "1.3.6.1.5.5.7.48.1": "OCSP",
  "1.3.6.1.5.5.7.48.1.5": "id-pkix-ocsp-nocheck",
  "1.3.6.1.5.5.7.48.2": "id-ad-caIssuers",

  "1.3.132.0.34": "secp384r1",

  "2.5.29.15": "id-ce-keyUsage",
  "2.5.29.17": "id-ce-subjectAltName",
  "2.5.29.19": "id-ce-basicConstraints",
  "2.5.29.30": "id-ce-nameConstraints",
  "2.5.29.32": "id-ce-certificatePolicies",
  "2.5.29.32.0": "anyPolicy",
  "2.5.29.36": "id-ce-policyConstraints",
  "2.5.29.37": "id-ce-extKeyUsage",
  "2.5.29.54": "id-ce-inhibitAnyPolicy",

  "2.5.4.3": "id-at-commonName",
  "2.5.4.5": "id-at-serialNumber",
  "2.5.4.6": "id-at-countryName",
  "2.5.4.7": "id-at-localityName",
  "2.5.4.8": "id-at-stateOrProvinceName",
  "2.5.4.9": "id-at-streetAddress",
  "2.5.4.10": "id-at-organizationName",
  "2.5.4.11": "id-at-organizationalUnitName",
};

class DecodedDER {
  constructor(der) {
    this._der = der;
    this._error = null;
  }

  get error() {
    return this._error;
  }

  parseOverride() {
    throw new LintX509Error(ERROR_LIBRARY_FAILURE);
  }

  parse() {
    try {
      this.parseOverride();
    } catch (e) {
      this._error = e;
    }
  }
}

class Certificate extends DecodedDER {
  constructor(der) {
    super(der);
    this._tbsCertificate = null;
    this._signatureAlgorithm = null;
    this._signatureValue = null;
  }

  get tbsCertificate() {
    return this._tbsCertificate;
  }

  get signatureAlgorithm() {
    return this._signatureAlgorithm;
  }

  get signatureValue() {
    return this._signatureValue;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();
    this._tbsCertificate = new TBSCertificate(contents.readTLV());
    this._tbsCertificate.parse();

    this._signatureAlgorithm = new AlgorithmIdentifier(contents.readTLV());
    this._signatureAlgorithm.parse();

    let signatureValue = contents.readBITSTRING();
    if (signatureValue.unusedBits != 0) {
      throw new LintX509Error(ERROR_UNSUPPORTED_ASN1);
    }
    this._signatureValue = new ByteArray(signatureValue.contents, "");
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class TBSCertificate extends DecodedDER {
  constructor(der) {
    super(der);
    this._version = null;
    this._serialNumber = null;
    this._signature = null;
    this._issuer = null;
    this._validity = null;
    this._subject = null;
    this._subjectPublicKeyInfo = null;
    this._extensions = null;
  }

  get version() {
    return this._version;
  }

  get serialNumber() {
    return this._serialNumber;
  }

  get signature() {
    return this._signature;
  }

  get issuer() {
    return this._issuer;
  }

  get validity() {
    return this._validity;
  }

  get subject() {
    return this._subject;
  }

  get subjectPublicKeyInfo() {
    return this._subjectPublicKeyInfo;
  }

  get extensions() {
    return this._extensions;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();

    let versionTag = CONTEXT_SPECIFIC | CONSTRUCTED | 0;
    if (!contents.peekTag(versionTag)) {
      this._version = 1;
    } else {
      let versionContents = contents.readGivenTag(versionTag);
      let versionBytes = versionContents.readINTEGER();
      if (versionBytes.length != 1 || versionBytes[0] != X509v3) {
        throw new LintX509Error(ERROR_UNSUPPORTED_VERSION);
      }
      this._version = 3;
      versionContents.assertAtEnd();
    }

    this._serialNumber = new ByteArray(contents.readINTEGER(), ":");

    this._signature = new AlgorithmIdentifier(contents.readTLV());
    this._signature.parse();

    this._issuer = new Name(contents.readTLV());
    this._issuer.parse();

    this._validity = new Validity(contents.readTLV());
    this._validity.parse();

    this._subject = new Name(contents.readTLV());
    this._subject.parse();

    this._subjectPublicKeyInfo = new SubjectPublicKeyInfo(
      contents.readTLV());
    this._subjectPublicKeyInfo.parse();

    let issuerUniqueIDTag = CONTEXT_SPECIFIC | CONSTRUCTED | 1;
    if (contents.peekTag(issuerUniqueIDTag)) {
      throw new LintX509Error(ERROR_UNSUPPORTED_X509_FEATURE);
    }
    let subjectUniqueIDTag = CONTEXT_SPECIFIC | CONSTRUCTED | 2;
    if (contents.peekTag(subjectUniqueIDTag)) {
      throw new LintX509Error(ERROR_UNSUPPORTED_X509_FEATURE);
    }

    let extensionsTag = CONTEXT_SPECIFIC | CONSTRUCTED | 3;
    if (contents.peekTag(extensionsTag)) {
      let extensionsSequence = contents.readGivenTag(extensionsTag);
      this._extensions = [];
      let extensionsContents = extensionsSequence.readSEQUENCE();
      while (!extensionsContents.atEnd()) {
        let extension = new Extension(extensionsContents.readTLV());
        extension.parse();
        this._extensions.push(extension);
      }
      extensionsContents.assertAtEnd();
      extensionsSequence.assertAtEnd();
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class ByteArray {
  constructor(bytesOrDER, displayDelimiter) {
    this._bytes = bytesOrDER instanceof DER
                ? bytesOrDER.readBytes(bytesOrDER.getRemainingLength())
                : bytesOrDER;
    this._displayDelimiter = displayDelimiter;
  }

  get length() {
    return this._bytes.length;
  }

  toString() {
    let output = "";
    for (let i in this._bytes) {
      let hexByte = this._bytes[i].toString(16);
      if (hexByte.length == 1) {
        hexByte = "0" + hexByte;
      }
      output += (output.length != 0 ? this._displayDelimiter : "") + hexByte;
    }
    return output;
  }
}

class AlgorithmIdentifier extends DecodedDER {
  constructor(der) {
    super(der);
    this._algorithm = null;
    this._parameters = null;
  }

  get algorithm() {
    return this._algorithm;
  }

  get parameters() {
    return this._parameters;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();
    this._algorithm = contents.readOID();
    if (!contents.atEnd()) {
      if (contents.peekTag(NULL)) {
        this._parameters = contents.readNULL();
      } else if (contents.peekTag(OBJECT_IDENTIFIER)) {
        this._parameters = contents.readOID();
      } else {
        throw new LintX509Error(ERROR_UNKNOWN_ALGORITHM_IDENTIFIER_PARAMS);
      }
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class Name extends DecodedDER {
  constructor(der) {
    super(der);
    this._rdns = null;
  }

  get rdns() {
    return this._rdns;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();
    this._rdns = [];
    while (!contents.atEnd()) {
      let rdn = new RDN(contents.readTLV());
      rdn.parse();
      this._rdns.push(rdn);
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }

  toString() {
    let result = "";
    for (let rdn of this.rdns) {
      for (let ava of rdn.avas) {
        result += (result ? "\n" : "") + ava.type.toString() + ": " +
                  ava.value.toString();
      }
    }
    return result;
  }
}

class RDN extends DecodedDER {
  constructor(der) {
    super(der);
    this._avas = null;
  }

  get avas() {
    return this._avas;
  }

  parseOverride() {
    let contents = this._der.readSET();
    this._avas = [];
    while (!contents.atEnd()) {
      let ava = new AVA(contents.readTLV());
      ava.parse();
      this._avas.push(ava);
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class AVA extends DecodedDER {
  constructor(der) {
    super(der);
    this._type = null;
    this._value = null;
  }

  get type() {
    return this._type;
  }

  get value() {
    return this._value;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();
    this._type = contents.readOID();
    this._value = new DirectoryString(
      contents.readTLVChoice([UTF8String, PrintableString, TeletexString,
                              IA5String]));
    this._value.parse();
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class DirectoryString extends DecodedDER {
  constructor(der) {
    super(der);
    this._type = null;
    this._value = null;
    this._asString = null;
  }

  get type() {
    return this._type;
  }

  get value() {
    return this._value;
  }

  parseOverride() {
    if (this._der.peekTag(UTF8String)) {
      this._type = UTF8String;
    } else if (this._der.peekTag(PrintableString)) {
      this._type = PrintableString;
    } else if (this._der.peekTag(TeletexString)) {
      this._type = TeletexString;
    } else if (this._der.peekTag(IA5String)) {
      this._type = IA5String;
    } else {
      throw new LintX509Error(ERROR_UNSUPPORTED_STRING_TYPE);
    }
    // TODO: validate that the contents are actually valid for the type
    this._value = this._der.readContents(this._type);
    this._asString = utf8BytesToString(this._value);
    this._der.assertAtEnd();
  }

  toString() {
    return this._asString;
  }
}

function utf8BytesToString(bytes) {
  let result = "";
  let i = 0;
  while (i < bytes.length) {
    let byte1 = bytes[i];
    i++;
    if ((byte1 >> 7) == 0) {
      // If the next byte is of the form 0xxxxxxx, this codepoint consists of
      // one byte.
      result += String.fromCharCode(byte1);
    } else if ((byte1 >> 5) == 6) {
      // If the next byte is of the form 110xxxxx, this codepoint consists of
      // two bytes. The other byte must be of the form 10xxxxxx.
      if (i >= bytes.length) {
        throw new LintX509Error(ERROR_INVALID_UTF8_ENCODING);
      }
      let byte2 = bytes[i];
      i++;
      if ((byte2 >> 6) != 2) {
        throw LintX509Error(ERROR_INVALID_UTF8_ENCODING);
      }
      let codepoint = ((byte1 & 0x1F) << 6) + (byte2 & 0x3F);
      result += String.fromCharCode(codepoint);
    } else if ((byte1 >> 4) == 0x0E) {
      // If the next byte is of the form 1110xxxx, this codepoint consists of
      // three bytes. The next two bytes must be of the form 10xxxxxx 10xxxxxx.
      if (i >= bytes.length) {
        throw new LintX509Error(ERROR_INVALID_UTF8_ENCODING);
      }
      let byte2 = bytes[i];
      i++;
      if ((byte2 >> 6) != 2) {
        throw new LintX509Error(ERROR_INVALID_UTF8_ENCODING);
      }
      if (i >= bytes.length) {
        throw new LintX509Error(ERROR_INVALID_UTF8_ENCODING);
      }
      let byte3 = bytes[i];
      i++;
      if ((byte3 >> 6) != 2) {
        throw new LintX509Error(ERROR_INVALID_UTF8_ENCODING);
      }
      let codepoint = ((byte1 & 0x1F) << 12) + ((byte2 & 0x3F) << 6) +
                      (byte3 & 0x3F);
      result += String.fromCharCode(codepoint);
    } else {
      throw new LintX509Error(ERROR_INVALID_UTF8_ENCODING);
    }
  }
  return result;
}

// TODO: Validate that the Time doesn't specify a nonexistent month/day/etc.
class Time extends DecodedDER {
  constructor(der) {
    super(der);
    this._type = null;
    this._time = null;
  }

  get time() {
    return this._time;
  }

  parseOverride() {
    if (this._der.peekTag(UTCTime)) {
      this._type = UTCTime;
    } else if (this._der.peekTag(GeneralizedTime)) {
      this._type = GeneralizedTime;
    } else {
      throw new LintX509Error(ERROR_TIME_NOT_UTCTIME_OR_GENERALIZED_TIME);
    }
    let contents = this._der.readGivenTag(this._type);
    let year;
    if (this._type == UTCTime) {
      // UTCTime is YYMMDDHHMMSSZ in RFC 5280. If YY is greater than or equal
      // to 50, the year is 19YY. Otherwise, it is 20YY.
      let y1 = this._validateDigit(contents.readByte());
      let y2 = this._validateDigit(contents.readByte());
      let yy = y1 * 10 + y2;
      if (yy >= 50) {
        year = 1900 + yy;
      } else {
        year = 2000 + yy;
      }
    } else {
      // GeneralizedTime is YYYYMMDDHHMMSSZ in RFC 5280.
      year = 0;
      for (let i = 0; i < 4; i++) {
        let y = this._validateDigit(contents.readByte());
        year = year * 10 + y;
      }
    }

    let m1 = this._validateDigit(contents.readByte());
    let m2 = this._validateDigit(contents.readByte());
    let month = m1 * 10 + m2;

    let d1 = this._validateDigit(contents.readByte());
    let d2 = this._validateDigit(contents.readByte());
    let day = d1 * 10 + d2;

    let h1 = this._validateDigit(contents.readByte());
    let h2 = this._validateDigit(contents.readByte());
    let hour = h1 * 10 + h2;

    let min1 = this._validateDigit(contents.readByte());
    let min2 = this._validateDigit(contents.readByte());
    let minute = min1 * 10 + min2;

    let s1 = this._validateDigit(contents.readByte());
    let s2 = this._validateDigit(contents.readByte());
    let second = s1 * 10 + s2;

    let z = contents.readByte();
    if (z != 'Z'.charCodeAt(0)) {
      throw new LintX509Error(ERROR_TIME_NOT_VALID);
    }
    // months are zero-indexed in JS
    this._time = new Date(Date.UTC(year, month - 1, day, hour, minute,
                                   second));

    contents.assertAtEnd();
    this._der.assertAtEnd();
  }

  // Takes a byte that is supposed to be in the ASCII range for '0' to '9'.
  // Validates the range and then converts it to the range 0 to 9.
  _validateDigit(d) {
    if (d < '0'.charCodeAt(0) || d > '9'.charCodeAt(0)) {
      throw new LintX509Error(ERROR_TIME_NOT_VALID);
    }
    return d - '0'.charCodeAt(0);
  }

  toString() {
    return this._time.toISOString();
  }
}

class Validity extends DecodedDER {
  constructor(der) {
    super(der);
    this._notBefore = null;
    this._notAfter = null;
  }

  get notBefore() {
    return this._notBefore;
  }

  get notAfter() {
    return this._notAfter;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();

    this._notBefore = new Time(
      contents.readTLVChoice([UTCTime, GeneralizedTime]));
    this._notBefore.parse();

    this._notAfter = new Time(
      contents.readTLVChoice([UTCTime, GeneralizedTime]));
    this._notAfter.parse();

    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class RSAPublicKey extends DecodedDER {
  constructor(der) {
    super(der);
    this._modulus = null;
    this._publicExponent = null;
  }

  get modulus() {
    return this._modulus;
  }

  get publicExponent() {
    return this._publicExponent;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();

    this._modulus = new ByteArray(contents.readINTEGER(), " ");

    this._publicExponent = new ByteArray(contents.readINTEGER(), " ");

    contents.assertAtEnd();
    this._der.assertAtEnd();
  }

  toString() {
    return this.modulus.toString() + "\n" + this.publicExponent.toString();
  }
}

class ECPublicKey extends DecodedDER {
  constructor(der) {
    super(der);
    this._x = null;
    this._y = null;
  }

  get x() {
    return this._x;
  }

  get y() {
    return this._y;
  }

  parseOverride() {
    if (this._der.readByte() != EC_UNCOMPRESSED_FORM) {
      throw new LintX509Error(ERROR_UNSUPPORTED_EC_PUBLIC_KEY);
    }
    let remainingLength = this._der.getRemainingLength();
    if (remainingLength % 2 != 0) {
      throw new LintX509Error(ERROR_UNSUPPORTED_EC_PUBLIC_KEY);
    }
    let pointLength = remainingLength / 2;
    this._x = new ByteArray(this._der.readBytes(pointLength), "");
    this._y = new ByteArray(this._der.readBytes(pointLength), "");

    this._der.assertAtEnd();
  }

  toString() {
    return this.x.toString() + "\n" + this.y.toString();
  }
}

class SubjectPublicKeyInfo extends DecodedDER {
  constructor(der) {
    super(der);
    this._algorithm = null;
    this._subjectPublicKey = null;
  }

  get algorithm() {
    return this._algorithm;
  }

  get subjectPublicKey() {
    return this._subjectPublicKey;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();

    this._algorithm = new AlgorithmIdentifier(contents.readTLV());
    this._algorithm.parse();

    let subjectPublicKeyBitString = contents.readBITSTRING();
    if (subjectPublicKeyBitString.unusedBits != 0) {
      throw new LintX509Error(ERROR_UNSUPPORTED_ASN1);
    }
    if (this._algorithm.algorithm.toString() == "rsaEncryption") {
      this._subjectPublicKey = new RSAPublicKey(
        new DER(subjectPublicKeyBitString.contents));
      this._subjectPublicKey.parse();
    } else if (this._algorithm.algorithm.toString() == "ecPublicKey") {
      this._subjectPublicKey = new ECPublicKey(
        new DER(subjectPublicKeyBitString.contents));
      this._subjectPublicKey.parse();
    } else {
      this._subjectPublicKey = new ByteArray(
        subjectPublicKeyBitString.contents, "");
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

const KeyUsages = {
  digitalSignature: 0,
  nonRepudiation: 1,
  keyEncipherment: 2,
  dataEncipherment: 3,
  keyAgreement: 4,
  keyCertSign: 5,
  cRLSign: 6,
  encipherOnly: 7,
  decipherOnly: 8,
};

class KeyUsage extends DecodedDER {
  constructor(der) {
    super(der);
    this._usages = null;
  }

  get usages() {
    return this._usages;
  }

  parseOverride() {
    this._usages = [];
    let bitstring = this._der.readBITSTRING();
    // readBITSTRING guarantees at least one byte of contents
    let firstByte = bitstring.contents[0];
    let secondByte = bitstring.contents.length > 1
                   ? bitstring.contents[1]
                   : null;
    Object.keys(KeyUsages).forEach(usage => {
      let bitIndex = KeyUsages[usage];
      if (bitIndex < 8) {
        if (firstByte & (1 << (8 - bitIndex - 1))) {
          this._usages.push(usage);
        }
      } else if (secondByte && (secondByte & 0x80)) {
        this._usages.push(usage);
      }
    });
    this._der.assertAtEnd();
  }
}

// This isn't really DER, but reusing the framework makes it easier to decode.
class IPAddress extends DecodedDER {
  constructor(der) {
    super(der);
    this._asString = null;
  }

  parseOverride() {
    let length = this._der.getRemainingLength();
    if (length != 4 && length != 8) {
      throw new LintX509Error(ERROR_UNSUPPORTED_IP_ADDRESS);
    }

    let address = this._der.readBytes(4);
    this._asString = address.join(".");
    if (!this._der.atEnd()) {
      let mask = this._der.readBytes(4);
      this._asString += "/" + mask.join(".");
    }
    this._der.assertAtEnd();
  }

  toString() {
    return this._asString;
  }
}

const rfc822Name = CONTEXT_SPECIFIC | 1;
const dNSName = CONTEXT_SPECIFIC | 2;
const directoryName = CONTEXT_SPECIFIC | CONSTRUCTED | 4;
const uniformResourceIdentifier = CONTEXT_SPECIFIC | 6;
const iPAddress = CONTEXT_SPECIFIC | 7;

class GeneralName extends DecodedDER {
  constructor(der) {
    super(der);
    this._type = null;
    this._value = null;
  }

  get type() {
    return this._type;
  }

  get value() {
    return this._value;
  }

  parseOverride() {
    if (this._der.peekTag(rfc822Name)) {
      this._type = rfc822Name;
      this._value = new ASCIIString(
        this._der.readTagAndGetContents(rfc822Name));
    } else if (this._der.peekTag(dNSName)) {
      this._type = dNSName;
      this._value = new ASCIIString(this._der.readTagAndGetContents(dNSName));
    } else if (this._der.peekTag(directoryName)) {
      this._type = directoryName;
      this._value = new Name(this._der.readGivenTag(directoryName));
      this._value.parse();
    } else if (this._der.peekTag(uniformResourceIdentifier)) {
      this._type = uniformResourceIdentifier;
      this._value = new ASCIIString(
        this._der.readTagAndGetContents(uniformResourceIdentifier));
    } else if (this._der.peekTag(iPAddress)) {
      this._type = iPAddress;
      this._value = new IPAddress(this._der.readGivenTag(iPAddress));
      this._value.parse();
    } else {
      throw new LintX509Error(ERROR_UNSUPPORTED_GENERAL_NAME_TYPE);
    }
    this._der.assertAtEnd();
  }
}

class SubjectAltName extends DecodedDER {
  constructor(der) {
    super(der);
    this._generalNames = [];
  }

  get generalNames() {
    return this._generalNames;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();

    while (!contents.atEnd()) {
      this._generalNames = [];
      while (!contents.atEnd()) {
        let generalName = new GeneralName(contents.readTLV());
        generalName.parse();
        this._generalNames.push(generalName);
      }
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class BasicConstraints extends DecodedDER {
  constructor(der) {
    super(der);
    this._cA = null;
    this._pathLenConstraint = null;
  }

  get cA() {
    return this._cA;
  }

  get pathLenConstraint() {
    return this._pathLenConstraint;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();

    // TODO: check for explicit encoding of DEFAULT FALSE
    if (contents.peekTag(BOOLEAN)) {
      let cAValue = contents.readBOOLEAN();
      if (cAValue == 0xff) {
        this._cA = true;
      } else if (cAValue == 0x00) {
        this._cA = false;
      } else {
        throw new LintX509Error(ERROR_LIBRARY_FAILURE);
      }
    } else {
      this._cA = false;
    }

    if (contents.peekTag(INTEGER)) {
      let pathLenConstraintBytes = contents.readINTEGER();
      if (pathLenConstraintBytes.length != 1) {
        throw new LintX509Error(ERROR_UNSUPPORTED_EXTENSION_VALUE);
      }
      this._pathLenConstraint = pathLenConstraintBytes[0];
    }

    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class GeneralSubtree extends DecodedDER {
  constructor(der) {
    super(der);
    this._base = null;
    // Note that under RFC 5280, for a GeneralSubtree, the minimum must be the
    // default 0 and the maximum must not be present. Thus, this really only
    // consists of the base GeneralName.
  }

  get base() {
    return this._base;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();
    this._base = new GeneralName(contents.readTLV());
    this._base.parse();
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class NameConstraints extends DecodedDER {
  constructor(der) {
    super(der);
    this._permittedSubtrees = null;
    this._excludedSubtrees = null;
  }

  get permittedSubtrees() {
    return this._permittedSubtrees;
  }

  get excludedSubtrees() {
    return this._excludedSubtrees;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();

    let permittedSubtreesTag = CONTEXT_SPECIFIC | CONSTRUCTED | 0;
    if (contents.peekTag(permittedSubtreesTag)) {
      this._permittedSubtrees = [];
      let permittedSubtreesContents =
        contents.readGivenTag(permittedSubtreesTag);
      while (!permittedSubtreesContents.atEnd()) {
        let permittedSubtree = new GeneralSubtree(
          permittedSubtreesContents.readTLV());
        permittedSubtree.parse();
        this._permittedSubtrees.push(permittedSubtree);
      }
    }

    let excludedSubtreesTag = CONTEXT_SPECIFIC | CONSTRUCTED | 1;
    if (contents.peekTag(excludedSubtreesTag)) {
      this._excludedSubtrees = [];
      let excludedSubtreesContents =
        contents.readGivenTag(excludedSubtreesTag);
      while (!excludedSubtreesContents.atEnd()) {
        let excludedSubtree = new GeneralSubtree(
          excludedSubtreesContents.readTLV());
        excludedSubtree.parse();
        this._excludedSubtrees.push(excludedSubtree);
      }
    }

    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class PolicyInformation extends DecodedDER {
  constructor(der) {
    super(der);
    this._policyIdentifier = null;
    this._policyQualifiers = null;
  }

  get policyIdentifier() {
    return this._policyIdentifier;
  }

  get policyQualifiers() {
    return this._policyQualifiers;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();

    this._policyIdentifier = contents.readOID();

    // TODO: we could parse all this out, but it doesn't actually make a
    // difference to mozilla::pkix, so it's not very important.
    this._policyQualifiers = new ByteArray(contents.readTLV(), " ");

    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class CertificatePolicies extends DecodedDER {
  constructor(der) {
    super(der);
    this._policyInformation = null;
  }

  get policyInformation() {
    return this._policyInformation;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();
    this._policyInformation = [];
    while (!contents.atEnd()) {
      let policyInformation = new PolicyInformation(contents.readTLV());
      policyInformation.parse();
      this._policyInformation.push(policyInformation);
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class ExtKeyUsage extends DecodedDER {
  constructor(der) {
    super(der);
    this._keyPurposeIds = null;
  }

  get keyPurposeIds() {
    return this._keyPurposeIds;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();
    this._keyPurposeIds = [];
    while (!contents.atEnd()) {
      this._keyPurposeIds.push(contents.readOID());
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class InhibitAnyPolicy extends DecodedDER {
  constructor(der) {
    super(der);
    this._skipCerts = null;
  }

  get skipCerts() {
    return this._skipCerts;
  }

  parseOverride() {
    // TODO: automatically handle integers that are small enough to display
    // not as byte arrays
    this._skipCerts = new ByteArray(this._der.readINTEGER(), " ");
    this._der.assertAtEnd();
  }
}

class AccessDescription extends DecodedDER {
  constructor(der) {
    super(der);
    this._accessMethod = null;
    this._accessLocation = null;
  }

  get accessMethod() {
    return this._accessMethod;
  }

  get accessLocation() {
    return this._accessLocation;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();

    this._accessMethod = contents.readOID();
    this._accessLocation = new GeneralName(contents.readTLV());
    this._accessLocation.parse();

    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class AuthorityInfoAccess extends DecodedDER {
  constructor(der) {
    super(der);
    this._accessDescriptions = null;
  }

  get accessDescriptions() {
    return this._accessDescriptions;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();

    this._accessDescriptions = [];
    while (!contents.atEnd()) {
      let accessDescription = new AccessDescription(contents.readTLV());
      accessDescription.parse();
      this._accessDescriptions.push(accessDescription);
    }

    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

class OCSPNoCheck extends DecodedDER {
  constructor(der) {
    super(der);
    this._value = null;
  }

  get value() {
    return this._value;
  }

  parseOverride() {
    this._value = this._der.readNULL();
    this._der.assertAtEnd();
  }
}

class TLSFeature extends DecodedDER {
  constructor(der) {
    super(der);
    this._features = null;
  }

  get features() {
    return this._features;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();
    this._features = [];
    while (!contents.atEnd()) {
      this._features.push(new ByteArray(contents.readINTEGER(), ":"));
    }
  }
}

class EmbeddedSCTList extends DecodedDER {
  constructor(der) {
    super(der);
    this._value = null;
  }

  get value() {
    return this._value;
  }

  parseOverride() {
    this._value = new ByteArray(this._der.readOCTETSTRING(), " ");
    this._der.assertAtEnd();
  }
}

var KnownExtensions = {
  "id-ce-keyUsage": KeyUsage,
  "id-ce-subjectAltName": SubjectAltName,
  "id-ce-basicConstraints": BasicConstraints,
  "id-ce-nameConstraints": NameConstraints,
  "id-ce-certificatePolicies": CertificatePolicies,
  "id-ce-extKeyUsage": ExtKeyUsage,
  "id-ce-inhibitAnyPolicy": InhibitAnyPolicy,
  "id-pe-authorityInfoAccess": AuthorityInfoAccess,
  "id-pkix-ocsp-nocheck": OCSPNoCheck,
  "id-pe-tlsfeature": TLSFeature,
  "id-embeddedSctList": EmbeddedSCTList,
};

class Extension extends DecodedDER {
  constructor(der) {
    super(der);
    this._extnID = null;
    this._critical = null;
    this._extnValue = null;
  }

  get extnID() {
    return this._extnID;
  }

  get critical() {
    return this._critical;
  }

  get extnValue() {
    return this._extnValue;
  }

  parseOverride() {
    let contents = this._der.readSEQUENCE();

    this._extnID = contents.readOID();

    // TODO: check for explicit encoding of DEFAULT FALSE
    if (contents.peekTag(BOOLEAN)) {
      let criticalValue = contents.readBOOLEAN();
      if (criticalValue == 0xff) {
        this._critical = true;
      } else if (criticalValue == 0x00) {
        this._critical = false;
      } else {
        throw new LintX509Error(ERROR_LIBRARY_FAILURE);
      }
    } else {
      this._critical = false;
    }

    this._extnValue = contents.readOCTETSTRING();
    if (this._extnID.toString() in KnownExtensions) {
      let extensionType = KnownExtensions[this._extnID.toString()];
      this._extnValue = new extensionType(new DER(this._extnValue));
      this._extnValue.parse();
    }
    contents.assertAtEnd();
    this._der.assertAtEnd();
  }
}

this.lintx509 = { Certificate, TBSCertificate, DER };
this.EXPORTED_SYMBOLS = ["lintx509"];

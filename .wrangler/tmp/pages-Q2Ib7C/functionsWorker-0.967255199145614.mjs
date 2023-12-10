var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// ../.wrangler/tmp/bundle-r7CdKT/checked-fetch.js
function checkURL(request, init) {
  const url = request instanceof URL ? request : new URL(
    (typeof request === "string" ? new Request(request, init) : request).url
  );
  if (url.port && url.port !== "443" && url.protocol === "https:") {
    if (!urls.has(url.toString())) {
      urls.add(url.toString());
      console.warn(
        `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
      );
    }
  }
}
var urls;
var init_checked_fetch = __esm({
  "../.wrangler/tmp/bundle-r7CdKT/checked-fetch.js"() {
    urls = /* @__PURE__ */ new Set();
    globalThis.fetch = new Proxy(globalThis.fetch, {
      apply(target, thisArg, argArray) {
        const [request, init] = argArray;
        checkURL(request, init);
        return Reflect.apply(target, thisArg, argArray);
      }
    });
  }
});

// wrangler-modules-watch:wrangler:modules-watch
var init_wrangler_modules_watch = __esm({
  "wrangler-modules-watch:wrangler:modules-watch"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
  }
});

// ../../../../../../../../usr/local/lib/node_modules/wrangler/templates/modules-watch-stub.js
var init_modules_watch_stub = __esm({
  "../../../../../../../../usr/local/lib/node_modules/wrangler/templates/modules-watch-stub.js"() {
    init_wrangler_modules_watch();
  }
});

// ../node_modules/@tsndr/cloudflare-worker-jwt/index.js
var require_cloudflare_worker_jwt = __commonJS({
  "../node_modules/@tsndr/cloudflare-worker-jwt/index.js"(exports, module) {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    var Base64URL = class {
      static parse(s) {
        return new Uint8Array(Array.prototype.map.call(atob(s.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "")), (c) => c.charCodeAt(0)));
      }
      static stringify(a) {
        return btoa(String.fromCharCode.apply(0, a)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
      }
    };
    var JWT = class {
      constructor() {
        if (typeof crypto === "undefined" || !crypto.subtle)
          throw new Error("Crypto not supported!");
        this.algorithms = {
          ES256: { name: "ECDSA", namedCurve: "P-256", hash: { name: "SHA-256" } },
          ES384: { name: "ECDSA", namedCurve: "P-384", hash: { name: "SHA-384" } },
          ES512: { name: "ECDSA", namedCurve: "P-521", hash: { name: "SHA-512" } },
          HS256: { name: "HMAC", hash: { name: "SHA-256" } },
          HS384: { name: "HMAC", hash: { name: "SHA-384" } },
          HS512: { name: "HMAC", hash: { name: "SHA-512" } },
          RS256: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
          RS384: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-384" } },
          RS512: { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-512" } }
        };
      }
      _utf8ToUint8Array(str) {
        return Base64URL.parse(btoa(unescape(encodeURIComponent(str))));
      }
      _str2ab(str) {
        const buf = new ArrayBuffer(str.length);
        const bufView = new Uint8Array(buf);
        for (let i = 0, strLen = str.length; i < strLen; i++) {
          bufView[i] = str.charCodeAt(i);
        }
        return buf;
      }
      _decodePayload(raw) {
        switch (raw.length % 4) {
          case 0:
            break;
          case 2:
            raw += "==";
            break;
          case 3:
            raw += "=";
            break;
          default:
            throw new Error("Illegal base64url string!");
        }
        try {
          return JSON.parse(decodeURIComponent(escape(atob(raw))));
        } catch {
          return null;
        }
      }
      async sign(payload, secret, options = { algorithm: "HS256", header: { typ: "JWT" } }) {
        if (typeof options === "string")
          options = { algorithm: options, header: { typ: "JWT" } };
        options = { algorithm: "HS256", header: { typ: "JWT" }, ...options };
        if (payload === null || typeof payload !== "object")
          throw new Error("payload must be an object");
        if (typeof secret !== "string")
          throw new Error("secret must be a string");
        if (typeof options.algorithm !== "string")
          throw new Error("options.algorithm must be a string");
        const importAlgorithm = this.algorithms[options.algorithm];
        if (!importAlgorithm)
          throw new Error("algorithm not found");
        payload.iat = Math.floor(Date.now() / 1e3);
        const payloadAsJSON = JSON.stringify(payload);
        const partialToken = `${Base64URL.stringify(this._utf8ToUint8Array(JSON.stringify({ ...options.header, alg: options.algorithm, kid: options.keyid })))}.${Base64URL.stringify(this._utf8ToUint8Array(payloadAsJSON))}`;
        let keyFormat = "raw";
        let keyData;
        if (secret.startsWith("-----BEGIN")) {
          keyFormat = "pkcs8";
          keyData = this._str2ab(atob(secret.replace(/-----BEGIN.*?-----/g, "").replace(/-----END.*?-----/g, "").replace(/\s/g, "")));
        } else
          keyData = this._utf8ToUint8Array(secret);
        const key = await crypto.subtle.importKey(keyFormat, keyData, importAlgorithm, false, ["sign"]);
        const signature = await crypto.subtle.sign(importAlgorithm, key, this._utf8ToUint8Array(partialToken));
        return `${partialToken}.${Base64URL.stringify(new Uint8Array(signature))}`;
      }
      async verify(token, secret, options = { algorithm: "HS256", throwError: false }) {
        if (typeof options === "string")
          options = { algorithm: options };
        options = { algorithm: "HS256", throwError: false, ...options };
        if (typeof token !== "string")
          throw new Error("token must be a string");
        if (typeof secret !== "string")
          throw new Error("secret must be a string");
        if (typeof options.algorithm !== "string")
          throw new Error("options.algorithm must be a string");
        const tokenParts = token.split(".");
        if (tokenParts.length !== 3)
          throw new Error("token must consist of 3 parts");
        const importAlgorithm = this.algorithms[options.algorithm];
        if (!importAlgorithm)
          throw new Error("algorithm not found");
        const { payload } = this.decode(token);
        if (payload.nbf && payload.nbf > Math.floor(Date.now() / 1e3)) {
          if (options.throwError)
            throw "NOT_YET_VALID";
          return false;
        }
        if (payload.exp && payload.exp <= Math.floor(Date.now() / 1e3)) {
          if (options.throwError)
            throw "EXPIRED";
          return false;
        }
        let keyFormat = "raw";
        let keyData;
        if (secret.startsWith("-----BEGIN")) {
          keyFormat = "spki";
          keyData = this._str2ab(atob(secret.replace(/-----BEGIN.*?-----/g, "").replace(/-----END.*?-----/g, "").replace(/\s/g, "")));
        } else
          keyData = this._utf8ToUint8Array(secret);
        const key = await crypto.subtle.importKey(keyFormat, keyData, importAlgorithm, false, ["verify"]);
        return await crypto.subtle.verify(importAlgorithm, key, Base64URL.parse(tokenParts[2]), this._utf8ToUint8Array(`${tokenParts[0]}.${tokenParts[1]}`));
      }
      decode(token) {
        return {
          header: this._decodePayload(token.split(".")[0].replace(/-/g, "+").replace(/_/g, "/")),
          payload: this._decodePayload(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))
        };
      }
    };
    module.exports = new JWT();
  }
});

// ../node_modules/uuid/dist/esm-browser/rng.js
function rng() {
  if (!getRandomValues) {
    getRandomValues = typeof crypto !== "undefined" && crypto.getRandomValues && crypto.getRandomValues.bind(crypto) || typeof msCrypto !== "undefined" && typeof msCrypto.getRandomValues === "function" && msCrypto.getRandomValues.bind(msCrypto);
    if (!getRandomValues) {
      throw new Error("crypto.getRandomValues() not supported. See https://github.com/uuidjs/uuid#getrandomvalues-not-supported");
    }
  }
  return getRandomValues(rnds8);
}
var getRandomValues, rnds8;
var init_rng = __esm({
  "../node_modules/uuid/dist/esm-browser/rng.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    rnds8 = new Uint8Array(16);
  }
});

// ../node_modules/uuid/dist/esm-browser/regex.js
var regex_default;
var init_regex = __esm({
  "../node_modules/uuid/dist/esm-browser/regex.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    regex_default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
  }
});

// ../node_modules/uuid/dist/esm-browser/validate.js
function validate(uuid3) {
  return typeof uuid3 === "string" && regex_default.test(uuid3);
}
var validate_default;
var init_validate = __esm({
  "../node_modules/uuid/dist/esm-browser/validate.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    init_regex();
    validate_default = validate;
  }
});

// ../node_modules/uuid/dist/esm-browser/stringify.js
function stringify(arr) {
  var offset = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : 0;
  var uuid3 = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
  if (!validate_default(uuid3)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid3;
}
var byteToHex, i, stringify_default;
var init_stringify = __esm({
  "../node_modules/uuid/dist/esm-browser/stringify.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    init_validate();
    byteToHex = [];
    for (i = 0; i < 256; ++i) {
      byteToHex.push((i + 256).toString(16).substr(1));
    }
    stringify_default = stringify;
  }
});

// ../node_modules/uuid/dist/esm-browser/v1.js
function v1(options, buf, offset) {
  var i = buf && offset || 0;
  var b = buf || new Array(16);
  options = options || {};
  var node = options.node || _nodeId;
  var clockseq = options.clockseq !== void 0 ? options.clockseq : _clockseq;
  if (node == null || clockseq == null) {
    var seedBytes = options.random || (options.rng || rng)();
    if (node == null) {
      node = _nodeId = [seedBytes[0] | 1, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }
    if (clockseq == null) {
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 16383;
    }
  }
  var msecs = options.msecs !== void 0 ? options.msecs : Date.now();
  var nsecs = options.nsecs !== void 0 ? options.nsecs : _lastNSecs + 1;
  var dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 1e4;
  if (dt < 0 && options.clockseq === void 0) {
    clockseq = clockseq + 1 & 16383;
  }
  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === void 0) {
    nsecs = 0;
  }
  if (nsecs >= 1e4) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }
  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq;
  msecs += 122192928e5;
  var tl = ((msecs & 268435455) * 1e4 + nsecs) % 4294967296;
  b[i++] = tl >>> 24 & 255;
  b[i++] = tl >>> 16 & 255;
  b[i++] = tl >>> 8 & 255;
  b[i++] = tl & 255;
  var tmh = msecs / 4294967296 * 1e4 & 268435455;
  b[i++] = tmh >>> 8 & 255;
  b[i++] = tmh & 255;
  b[i++] = tmh >>> 24 & 15 | 16;
  b[i++] = tmh >>> 16 & 255;
  b[i++] = clockseq >>> 8 | 128;
  b[i++] = clockseq & 255;
  for (var n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }
  return buf || stringify_default(b);
}
var _nodeId, _clockseq, _lastMSecs, _lastNSecs, v1_default;
var init_v1 = __esm({
  "../node_modules/uuid/dist/esm-browser/v1.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    init_rng();
    init_stringify();
    _lastMSecs = 0;
    _lastNSecs = 0;
    v1_default = v1;
  }
});

// ../node_modules/uuid/dist/esm-browser/parse.js
function parse(uuid3) {
  if (!validate_default(uuid3)) {
    throw TypeError("Invalid UUID");
  }
  var v;
  var arr = new Uint8Array(16);
  arr[0] = (v = parseInt(uuid3.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 255;
  arr[2] = v >>> 8 & 255;
  arr[3] = v & 255;
  arr[4] = (v = parseInt(uuid3.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 255;
  arr[6] = (v = parseInt(uuid3.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 255;
  arr[8] = (v = parseInt(uuid3.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 255;
  arr[10] = (v = parseInt(uuid3.slice(24, 36), 16)) / 1099511627776 & 255;
  arr[11] = v / 4294967296 & 255;
  arr[12] = v >>> 24 & 255;
  arr[13] = v >>> 16 & 255;
  arr[14] = v >>> 8 & 255;
  arr[15] = v & 255;
  return arr;
}
var parse_default;
var init_parse = __esm({
  "../node_modules/uuid/dist/esm-browser/parse.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    init_validate();
    parse_default = parse;
  }
});

// ../node_modules/uuid/dist/esm-browser/v35.js
function stringToBytes(str) {
  str = unescape(encodeURIComponent(str));
  var bytes = [];
  for (var i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }
  return bytes;
}
function v35_default(name, version2, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === "string") {
      value = stringToBytes(value);
    }
    if (typeof namespace === "string") {
      namespace = parse_default(namespace);
    }
    if (namespace.length !== 16) {
      throw TypeError("Namespace must be array-like (16 iterable integer values, 0-255)");
    }
    var bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 15 | version2;
    bytes[8] = bytes[8] & 63 | 128;
    if (buf) {
      offset = offset || 0;
      for (var i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }
      return buf;
    }
    return stringify_default(bytes);
  }
  try {
    generateUUID.name = name;
  } catch (err) {
  }
  generateUUID.DNS = DNS;
  generateUUID.URL = URL2;
  return generateUUID;
}
var DNS, URL2;
var init_v35 = __esm({
  "../node_modules/uuid/dist/esm-browser/v35.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    init_stringify();
    init_parse();
    DNS = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    URL2 = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
  }
});

// ../node_modules/uuid/dist/esm-browser/md5.js
function md5(bytes) {
  if (typeof bytes === "string") {
    var msg = unescape(encodeURIComponent(bytes));
    bytes = new Uint8Array(msg.length);
    for (var i = 0; i < msg.length; ++i) {
      bytes[i] = msg.charCodeAt(i);
    }
  }
  return md5ToHexEncodedArray(wordsToMd5(bytesToWords(bytes), bytes.length * 8));
}
function md5ToHexEncodedArray(input) {
  var output = [];
  var length32 = input.length * 32;
  var hexTab = "0123456789abcdef";
  for (var i = 0; i < length32; i += 8) {
    var x = input[i >> 5] >>> i % 32 & 255;
    var hex = parseInt(hexTab.charAt(x >>> 4 & 15) + hexTab.charAt(x & 15), 16);
    output.push(hex);
  }
  return output;
}
function getOutputLength(inputLength8) {
  return (inputLength8 + 64 >>> 9 << 4) + 14 + 1;
}
function wordsToMd5(x, len) {
  x[len >> 5] |= 128 << len % 32;
  x[getOutputLength(len) - 1] = len;
  var a = 1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d = 271733878;
  for (var i = 0; i < x.length; i += 16) {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    a = md5ff(a, b, c, d, x[i], 7, -680876936);
    d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
    c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
    b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
    a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
    d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
    c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
    b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
    a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
    d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
    c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
    b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
    a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
    d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
    c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
    b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);
    a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
    d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
    c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
    b = md5gg(b, c, d, a, x[i], 20, -373897302);
    a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
    d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
    c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
    b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
    a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
    d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
    c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
    b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
    a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
    d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
    c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
    b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);
    a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
    d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
    c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
    b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
    a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
    d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
    c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
    b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
    a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
    d = md5hh(d, a, b, c, x[i], 11, -358537222);
    c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
    b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
    a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
    d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
    c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
    b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);
    a = md5ii(a, b, c, d, x[i], 6, -198630844);
    d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
    c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
    b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
    a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
    d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
    c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
    b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
    a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
    d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
    c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
    b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
    a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
    d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
    c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
    b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);
    a = safeAdd(a, olda);
    b = safeAdd(b, oldb);
    c = safeAdd(c, oldc);
    d = safeAdd(d, oldd);
  }
  return [a, b, c, d];
}
function bytesToWords(input) {
  if (input.length === 0) {
    return [];
  }
  var length8 = input.length * 8;
  var output = new Uint32Array(getOutputLength(length8));
  for (var i = 0; i < length8; i += 8) {
    output[i >> 5] |= (input[i / 8] & 255) << i % 32;
  }
  return output;
}
function safeAdd(x, y) {
  var lsw = (x & 65535) + (y & 65535);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return msw << 16 | lsw & 65535;
}
function bitRotateLeft(num, cnt) {
  return num << cnt | num >>> 32 - cnt;
}
function md5cmn(q, a, b, x, s, t) {
  return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
}
function md5ff(a, b, c, d, x, s, t) {
  return md5cmn(b & c | ~b & d, a, b, x, s, t);
}
function md5gg(a, b, c, d, x, s, t) {
  return md5cmn(b & d | c & ~d, a, b, x, s, t);
}
function md5hh(a, b, c, d, x, s, t) {
  return md5cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5ii(a, b, c, d, x, s, t) {
  return md5cmn(c ^ (b | ~d), a, b, x, s, t);
}
var md5_default;
var init_md5 = __esm({
  "../node_modules/uuid/dist/esm-browser/md5.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    md5_default = md5;
  }
});

// ../node_modules/uuid/dist/esm-browser/v3.js
var v3, v3_default;
var init_v3 = __esm({
  "../node_modules/uuid/dist/esm-browser/v3.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    init_v35();
    init_md5();
    v3 = v35_default("v3", 48, md5_default);
    v3_default = v3;
  }
});

// ../node_modules/uuid/dist/esm-browser/v4.js
function v4(options, buf, offset) {
  options = options || {};
  var rnds = options.random || (options.rng || rng)();
  rnds[6] = rnds[6] & 15 | 64;
  rnds[8] = rnds[8] & 63 | 128;
  if (buf) {
    offset = offset || 0;
    for (var i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }
    return buf;
  }
  return stringify_default(rnds);
}
var v4_default;
var init_v4 = __esm({
  "../node_modules/uuid/dist/esm-browser/v4.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    init_rng();
    init_stringify();
    v4_default = v4;
  }
});

// ../node_modules/uuid/dist/esm-browser/sha1.js
function f(s, x, y, z) {
  switch (s) {
    case 0:
      return x & y ^ ~x & z;
    case 1:
      return x ^ y ^ z;
    case 2:
      return x & y ^ x & z ^ y & z;
    case 3:
      return x ^ y ^ z;
  }
}
function ROTL(x, n) {
  return x << n | x >>> 32 - n;
}
function sha1(bytes) {
  var K = [1518500249, 1859775393, 2400959708, 3395469782];
  var H = [1732584193, 4023233417, 2562383102, 271733878, 3285377520];
  if (typeof bytes === "string") {
    var msg = unescape(encodeURIComponent(bytes));
    bytes = [];
    for (var i = 0; i < msg.length; ++i) {
      bytes.push(msg.charCodeAt(i));
    }
  } else if (!Array.isArray(bytes)) {
    bytes = Array.prototype.slice.call(bytes);
  }
  bytes.push(128);
  var l = bytes.length / 4 + 2;
  var N = Math.ceil(l / 16);
  var M = new Array(N);
  for (var _i = 0; _i < N; ++_i) {
    var arr = new Uint32Array(16);
    for (var j = 0; j < 16; ++j) {
      arr[j] = bytes[_i * 64 + j * 4] << 24 | bytes[_i * 64 + j * 4 + 1] << 16 | bytes[_i * 64 + j * 4 + 2] << 8 | bytes[_i * 64 + j * 4 + 3];
    }
    M[_i] = arr;
  }
  M[N - 1][14] = (bytes.length - 1) * 8 / Math.pow(2, 32);
  M[N - 1][14] = Math.floor(M[N - 1][14]);
  M[N - 1][15] = (bytes.length - 1) * 8 & 4294967295;
  for (var _i2 = 0; _i2 < N; ++_i2) {
    var W = new Uint32Array(80);
    for (var t = 0; t < 16; ++t) {
      W[t] = M[_i2][t];
    }
    for (var _t = 16; _t < 80; ++_t) {
      W[_t] = ROTL(W[_t - 3] ^ W[_t - 8] ^ W[_t - 14] ^ W[_t - 16], 1);
    }
    var a = H[0];
    var b = H[1];
    var c = H[2];
    var d = H[3];
    var e = H[4];
    for (var _t2 = 0; _t2 < 80; ++_t2) {
      var s = Math.floor(_t2 / 20);
      var T = ROTL(a, 5) + f(s, b, c, d) + e + K[s] + W[_t2] >>> 0;
      e = d;
      d = c;
      c = ROTL(b, 30) >>> 0;
      b = a;
      a = T;
    }
    H[0] = H[0] + a >>> 0;
    H[1] = H[1] + b >>> 0;
    H[2] = H[2] + c >>> 0;
    H[3] = H[3] + d >>> 0;
    H[4] = H[4] + e >>> 0;
  }
  return [H[0] >> 24 & 255, H[0] >> 16 & 255, H[0] >> 8 & 255, H[0] & 255, H[1] >> 24 & 255, H[1] >> 16 & 255, H[1] >> 8 & 255, H[1] & 255, H[2] >> 24 & 255, H[2] >> 16 & 255, H[2] >> 8 & 255, H[2] & 255, H[3] >> 24 & 255, H[3] >> 16 & 255, H[3] >> 8 & 255, H[3] & 255, H[4] >> 24 & 255, H[4] >> 16 & 255, H[4] >> 8 & 255, H[4] & 255];
}
var sha1_default;
var init_sha1 = __esm({
  "../node_modules/uuid/dist/esm-browser/sha1.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    sha1_default = sha1;
  }
});

// ../node_modules/uuid/dist/esm-browser/v5.js
var v5, v5_default;
var init_v5 = __esm({
  "../node_modules/uuid/dist/esm-browser/v5.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    init_v35();
    init_sha1();
    v5 = v35_default("v5", 80, sha1_default);
    v5_default = v5;
  }
});

// ../node_modules/uuid/dist/esm-browser/nil.js
var nil_default;
var init_nil = __esm({
  "../node_modules/uuid/dist/esm-browser/nil.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    nil_default = "00000000-0000-0000-0000-000000000000";
  }
});

// ../node_modules/uuid/dist/esm-browser/version.js
function version(uuid3) {
  if (!validate_default(uuid3)) {
    throw TypeError("Invalid UUID");
  }
  return parseInt(uuid3.substr(14, 1), 16);
}
var version_default;
var init_version = __esm({
  "../node_modules/uuid/dist/esm-browser/version.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    init_validate();
    version_default = version;
  }
});

// ../node_modules/uuid/dist/esm-browser/index.js
var esm_browser_exports = {};
__export(esm_browser_exports, {
  NIL: () => nil_default,
  parse: () => parse_default,
  stringify: () => stringify_default,
  v1: () => v1_default,
  v3: () => v3_default,
  v4: () => v4_default,
  v5: () => v5_default,
  validate: () => validate_default,
  version: () => version_default
});
var init_esm_browser = __esm({
  "../node_modules/uuid/dist/esm-browser/index.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    init_v1();
    init_v3();
    init_v4();
    init_v5();
    init_nil();
    init_version();
    init_validate();
    init_stringify();
    init_parse();
  }
});

// api/admin/account.js
async function onRequestPost(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  let valid = 1;
  const contentType2 = request.headers.get("content-type");
  let registerData;
  if (contentType2 != null) {
    registerData = await request.json();
    console.log(registerData);
    if (registerData.action == 1) {
      const query = context.env.DB.prepare(`SELECT COUNT(*) as total from user where email = '${registerData.email}'`);
      const queryResult = await query.first();
      if (queryResult.total == 0) {
        let apiSecret = uuid.v4();
        let verifyCode = uuid.v4();
        const info = await context.env.DB.prepare("INSERT INTO user (username, email,password,apiSecret,confirmed,isBlocked,isAdmin,verifyCode) VALUES (?1, ?2,?3,?4,?5,?6,?7,?8)").bind(registerData.username, registerData.email, registerData.password, apiSecret, 0, 0, 0, verifyCode).run();
        if (info.success == true) {
          const data2 = {
            "templateId": context.env.SIGNUPEMAILTEMPLATEID,
            "to": registerData.email,
            "templateVariables": {
              "name": `${registerData.username}`,
              "product_name": `${context.env.PRODUCTNAME}`,
              "action_url": `${context.env.ADMINURL}verify?verifycode=${verifyCode}`,
              "login_url": `${context.env.ADMINURL}account-login`,
              "username": `${registerData.username}`,
              "sender_name": `${context.env.SENDEREMAILNAME}`
            }
          };
          const responseEmail = await fetch(context.env.EMAILAPIURL, {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify(data2)
          });
          const emailResponse = await responseEmail.json();
          return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
        } else
          return new Response(JSON.stringify({ error: "error registering" }), { status: 400 });
      } else {
        return new Response(JSON.stringify({ error: "email already exists" }), { status: 400 });
      }
    }
    if (registerData.action == 2) {
      if (registerData.email == void 0 || registerData.password == void 0)
        return new Response(JSON.stringify({ error: "invalid login" }), { status: 400 });
      const query = context.env.DB.prepare(`SELECT user.isDeleted,user.isBlocked,user.name,user.username,user.email,user.phone,user.id,user.isAdmin,userAccess.foreignId,user.apiSecret from user LEFT JOIN userAccess ON user.id = userAccess.userId where user.email = '${registerData.email}' and user.password = '${registerData.password}'`);
      const queryResult = await query.all();
      if (queryResult.results.length > 0) {
        let user = queryResult.results[0];
        if (user.isBlocked == 1)
          return new Response(JSON.stringify({ error: "user account is blocked" }), { status: 400 });
        if (user.isDeleted == 1)
          return new Response(JSON.stringify({ error: "user does not exist" }), { status: 400 });
        if (user.isAdmin == 1) {
          const query2 = context.env.DB.prepare(`SELECT COUNT(*) as total from property where isDeleted = 0`);
          const queryResult2 = await query2.first();
          user.foreignCount = queryResult2.total;
        } else {
          const query2 = context.env.DB.prepare(`SELECT COUNT(*) as total from property_owner where userId = ${user.id} and isDeleted = 0 `);
          const queryResult2 = await query2.first();
          user.foreignCount = queryResult2.total;
        }
        const token = await jwt.sign({ id: user.id, password: user.password, username: user.username, isAdmin: user.isAdmin }, env.SECRET);
        const isValid = await jwt.verify(token, env.SECRET);
        if (isValid == true) {
          return new Response(JSON.stringify({ "jwt": token, "user": { "id": user.id, "name": user.name, "username": user.username, "email": user.email, "phone": user.phone, "isAdmin": user.isAdmin, "foreignCount": user.foreignCount, "secret": user.apiSecret } }), { status: 200 });
        } else {
          return new Response(JSON.stringify({ error: "invalid login" }), { status: 400 });
        }
      } else {
        return new Response(JSON.stringify({ error: "username  / password issue" }), { status: 400 });
      }
    }
    if (registerData.action == 3) {
      const email = registerData.email;
      const query = context.env.DB.prepare(`SELECT COUNT(*) as total from user where email = '${email}'`);
      const queryResult = await query.first();
      if (queryResult.total > 0) {
        let verifyCode = uuid.v4();
        const stmt = await context.env.DB.prepare(`update user set resetPassword = 1,verifyCode='${verifyCode}'  where email = '${email}'`).run();
        if (stmt.success == true) {
          const query2 = context.env.DB.prepare(`SELECT username  from user where email = '${email}'`);
          const queryResult2 = await query2.first();
          const data2 = {
            "templateId": context.env.FORGOTPASSWORDEMAILTEMPLATEID,
            "to": email,
            "templateVariables": {
              "name": `${queryResult2.username}`,
              "product_name": `${context.env.PRODUCTNAME}`,
              "action_url": `${context.env.ADMINURL}reset-password?resetcode=${verifyCode}`
            }
          };
          const responseEmail = await fetch(context.env.EMAILAPIURL, {
            method: "POST",
            headers: {
              "Content-Type": "application/json"
            },
            body: JSON.stringify(data2)
          });
          const emailResponse = await responseEmail.json();
          return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
        } else
          return new Response(JSON.stringify({ error: "code not found" }), { status: 400 });
      } else {
        return new Response(JSON.stringify({ error: "email not found" }), { status: 400 });
      }
      return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
    }
    if (registerData.action == 4) {
      const verifyCode = registerData.verifycode;
      const query = context.env.DB.prepare(`SELECT COUNT(*) as total from user where verifyCode = '${verifyCode}'`);
      const queryResult = await query.first();
      if (queryResult.total > 0) {
        const stmt = await context.env.DB.prepare(`update user set isVerified = 1 where verifyCode = '${verifyCode}'`).run();
        if (stmt.success == true)
          return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
        else
          return new Response(JSON.stringify({ error: "code not found" }), { status: 400 });
      } else {
        return new Response(JSON.stringify({ error: "user not found" }), { status: 400 });
      }
    }
    if (registerData.action == 5) {
      const resetCode = registerData.resetcode;
      const password = registerData.password;
      const verifyCode = registerData.verifycode;
      const query = context.env.DB.prepare(`SELECT COUNT(*) as total from user where verifyCode = '${resetCode}'`);
      const queryResult = await query.first();
      if (queryResult.total > 0) {
        const stmt = await context.env.DB.prepare(`update user set resetPassword = 0,password='${password}',verifyCode = '' where verifyCode = '${resetCode}'`).run();
        if (stmt.success == true)
          return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
        else
          return new Response(JSON.stringify({ error: "code not found" }), { status: 400 });
      } else {
        return new Response(JSON.stringify({ error: "reset code not found" }), { status: 400 });
      }
    }
  } else {
    return new Response(JSON.stringify({ error: "Server error" }), { status: 400 });
  }
}
var jwt, uuid;
var init_account = __esm({
  "api/admin/account.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    jwt = require_cloudflare_worker_jwt();
    uuid = (init_esm_browser(), __toCommonJS(esm_browser_exports));
  }
});

// api/admin/email.js
async function onRequestGet(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  let theToken = await decodeJwt(request.headers, env.SECRET);
  if (theToken == "")
    return new Response(JSON.stringify({ error: "Token required" }), { status: 400 });
  if (theToken.payload.isAdmin == 1) {
    const { searchParams } = new URL(request.url);
    const emailType = searchParams.get("emailType");
    const email = searchParams.get("email");
    const orderId = searchParams.get("orderId");
    const tranches = searchParams.get("tranches");
    const name = searchParams.get("name");
    const total = searchParams.get("total");
    let emailData = "";
    if (emailType == "paymentLead") {
      emailData = {
        "templateId": context.env.PAYMENTLINKTEMPLATEID,
        "to": email,
        "templateVariables": {
          "tranches": `${tranches}`,
          "product_name": `${name}`,
          "action_url": `${context.env.PAYMEURL}payment/?orderId=${orderId}`,
          "total": `${total}`
        }
      };
    }
    console.log("emailData");
    console.log(emailData);
    console.log(context.env.EMAILAPIURL);
    const responseEmail = await fetch(context.env.EMAILAPIURL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(emailData)
    });
    const emailResponse = await responseEmail.json();
    console.log(emailResponse);
    return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
  } else {
    return new Response(JSON.stringify({ error: "naughty, you are not an admin" }), { status: 400 });
  }
}
var jwt2, decodeJwt;
var init_email = __esm({
  "api/admin/email.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    jwt2 = require_cloudflare_worker_jwt();
    decodeJwt = async (req, secret) => {
      let bearer = req.get("authorization");
      let details = "";
      if (bearer != null) {
        bearer = bearer.replace("Bearer ", "");
        details = await jwt2.decode(bearer, secret);
      }
      return details;
    };
  }
});

// api/admin/image.js
async function onRequestGet2(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  let theToken = await decodeJwt2(request.headers, env.SECRET);
  if (theToken == "")
    return new Response(JSON.stringify({ error: "Token required" }), { status: 400 });
  if (theToken.payload.isAdmin == 1) {
    const response = await fetch(context.env.CLOUDFLAREURL, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${context.env.BEARERTOKEN}`
      }
    });
    const cfresponse = await response.json();
    return new Response(JSON.stringify({ message: `Image has been updated`, url: `${cfresponse.result.uploadURL}` }), { status: 200 });
  } else {
    return new Response(JSON.stringify({ error: "naughty, you are not an admin" }), { status: 400 });
  }
}
var jwt3, decodeJwt2;
var init_image = __esm({
  "api/admin/image.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    jwt3 = require_cloudflare_worker_jwt();
    decodeJwt2 = async (req, secret) => {
      let bearer = req.get("authorization");
      console.log(bearer);
      let details = "";
      if (bearer != null) {
        bearer = bearer.replace("Bearer ", "");
        details = await jwt3.decode(bearer, secret);
      }
      return details;
    };
  }
});

// api/database/lookUp.js
async function onRequestGet3(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  let theToken = await decodeJwt3(request.headers, env.SECRET);
  const { searchParams } = new URL(request.url);
  let theData = searchParams.get("theData");
  theData = JSON.parse(theData);
  let query;
  let theResults = [];
  for (var i = 0; i < theData.length; ++i) {
    let theSQL = `SELECT id,name from ${theData[i].table}`;
    if (theData[i].foreignKey != "") {
      theSQL = theSQL + ` where ${theData[i].foreignKey} = ${theData[i].value}`;
      theSQL = theSQL + ` and isDeleted = 0`;
    } else {
      theSQL = theSQL + ` where isDeleted = 0`;
    }
    console.log(theSQL);
    query = context.env.DB.prepare(theSQL);
    let queryResults = await query.all();
    let theJson = { "table": theData[i].table, "key": theData[i].key, "theData": queryResults.results };
    theResults.push(theJson);
  }
  return new Response(JSON.stringify(theResults), { status: 200 });
}
var jwt4, decodeJwt3;
var init_lookUp = __esm({
  "api/database/lookUp.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    jwt4 = require_cloudflare_worker_jwt();
    decodeJwt3 = async (req, secret) => {
      let bearer = req.get("authorization");
      bearer = bearer.replace("Bearer ", "");
      let details = await jwt4.decode(bearer, secret);
      return details;
    };
  }
});

// api/database/schema.js
async function onRequestGet4(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  const { searchParams } = new URL(request.url);
  let tableName = searchParams.get("tablename");
  let fields = searchParams.get("fields");
  let fieldsArray = [];
  let finFields = [];
  if (fields != null)
    fieldsArray = fields.split(",");
  if (fields.includes(","))
    fieldsArray.push(fields);
  let query = context.env.DB.prepare(`PRAGMA table_info(${tableName});`);
  let queryResults = await query.all();
  if (fieldsArray[0] != "") {
    for (var i = 0; i < queryResults.results.length; ++i) {
      for (var i2 = 0; i2 < fieldsArray.length; ++i2) {
        if (fieldsArray[i2] == queryResults.results[i].name)
          finFields.push(queryResults.results[i]);
      }
    }
  } else {
    finFields = queryResults.results;
  }
  return new Response(JSON.stringify(finFields), { status: 200 });
}
var init_schema = __esm({
  "api/database/schema.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
  }
});

// api/database/table.js
async function onRequestPut(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  let theToken = await decodeJwt4(request.headers, env.SECRET);
  if (theToken.payload.isAdmin == 1) {
    const contentType2 = request.headers.get("content-type");
    let theData;
    if (contentType2 != null) {
      theData = await request.json();
      let theQuery = `UPDATE ${theData.table} SET `;
      let theQueryValues = "updatedAt = CURRENT_TIMESTAMP";
      let theQueryWhere = "";
      for (const key in theData.tableData) {
        let tdata = theData.tableData;
        if (key != "table" && key != "id") {
          theQueryValues = theQueryValues + `,${key} = '${tdata[key]}' `;
        }
        if (key == "id")
          theQueryWhere = ` where id = '${tdata[key]}'`;
      }
      theQuery = theQuery + theQueryValues + theQueryWhere;
      const info = await context.env.DB.prepare(theQuery).run();
      return new Response(JSON.stringify({ message: `${theData.table} has been updated` }), { status: 200 });
    }
    return new Response(JSON.stringify({ error: "server" }), { status: 400 });
  } else {
    return new Response(JSON.stringify({ error: "naughty, you are not an admin" }), { status: 400 });
  }
}
async function onRequestDelete(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  let theToken = await decodeJwt4(request.headers, env.SECRET);
  if (theToken.payload.isAdmin == 1) {
    const contentType2 = request.headers.get("content-type");
    let theData;
    if (contentType2 != null) {
      theData = await request.json();
      const info = await context.env.DB.prepare(`UPDATE ${theData.tableName} SET isDeleted = '1',deletedAt = CURRENT_TIMESTAMP WHERE id = ${theData.id}`).run();
      return new Response(JSON.stringify({ message: `${theData.tableName} has been deleted` }), { status: 200 });
    }
    return new Response(JSON.stringify({ error: "server" }), { status: 400 });
  } else {
    return new Response(JSON.stringify({ error: "naughty, you are not an admin" }), { status: 400 });
  }
}
async function onRequestPost2(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  let theToken = await decodeJwt4(request.headers, env.SECRET);
  if (theToken.payload.isAdmin == 1) {
    const contentType2 = request.headers.get("content-type");
    let theData;
    if (contentType2 != null) {
      theData = await request.json();
      let apiSecret = "";
      if (theData.table == "user")
        apiSecret = uuid2.v4();
      let theQuery = `INSERT INTO ${theData.table} (`;
      let theQueryFields = "";
      let theQueryValues = "";
      for (const key in theData.tableData) {
        let tdata = theData.tableData;
        if (key != "table") {
          if (theQueryFields == "")
            theQueryFields = `'${key}'`;
          else
            theQueryFields = theQueryFields + `,'${key}'`;
          if (theQueryValues == "")
            theQueryValues = `'${tdata[key]}'`;
          else
            theQueryValues = theQueryValues + `,'${tdata[key]}'`;
        }
      }
      theQuery = theQuery + theQueryFields + " ) VALUES ( " + theQueryValues + " ); ";
      console.log(theQuery);
      const info = await context.env.DB.prepare(theQuery).run();
      return new Response(JSON.stringify({ message: `${theData.table} has been added` }), { status: 200 });
    }
    return new Response(JSON.stringify({ error: "server" }), { status: 400 });
  } else {
    return new Response(JSON.stringify({ error: "naughty, you are not an admin" }), { status: 400 });
  }
}
async function onRequestGet5(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  let theToken = await decodeJwt4(request.headers, env.SECRET);
  if (theToken.payload.isAdmin == 1) {
    let query;
    let queryResults;
    const { searchParams } = new URL(request.url);
    let checkAdmin = 0;
    if (searchParams.get("checkAdmin") != null) {
      checkAdmin = searchParams.get("checkAdmin");
    }
    let foreignKey = "";
    if (searchParams.get("foreignKey") != null) {
      foreignKey = searchParams.get("foreignKey");
    }
    let tableName = searchParams.get("tablename");
    let fields = searchParams.get("fields");
    let recordId = "";
    if (searchParams.get("recordId") != null)
      recordId = searchParams.get("recordId");
    let schemaResults = [];
    let queryFin = {};
    let sqlWhere = `where ${tableName}.isDeleted = 0 `;
    if (recordId != "" && foreignKey == "")
      sqlWhere = sqlWhere + ` and id = ${recordId}`;
    if (checkAdmin != 0) {
      sqlWhere = sqlWhere + ` and ${tableName}.adminId = ${theToken.payload.id}`;
    }
    if (foreignKey != "" && recordId != "") {
      sqlWhere = sqlWhere + ` and ${foreignKey} = ${recordId}`;
    }
    let tmp = fields.split(",");
    let theQuery = "";
    if (tmp.length == 1) {
      theQuery = `SELECT * from ${tableName} ${sqlWhere} `;
      query = context.env.DB.prepare(theQuery);
    } else {
      let fields2 = "";
      for (var i = 0; i < tmp.length; ++i) {
        if (fields2 == "")
          fields2 = tmp[i];
        else
          fields2 = fields2 + "," + tmp[i];
      }
      theQuery = `SELECT ${fields2} from ${tableName} ${sqlWhere}`;
      console.log(theQuery);
      query = context.env.DB.prepare(theQuery);
    }
    queryResults = await query.all();
    queryFin.data = queryResults.results;
    return new Response(JSON.stringify(queryFin), { status: 200 });
  } else {
    return new Response(JSON.stringify({ error: "naughty, you are not an admin" }), { status: 400 });
  }
}
var jwt5, uuid2, decodeJwt4;
var init_table = __esm({
  "api/database/table.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    jwt5 = require_cloudflare_worker_jwt();
    uuid2 = (init_esm_browser(), __toCommonJS(esm_browser_exports));
    decodeJwt4 = async (req, secret) => {
      let bearer = req.get("authorization");
      bearer = bearer.replace("Bearer ", "");
      let details = await jwt5.decode(bearer, secret);
      return details;
    };
  }
});

// api/properties/crowdfund.js
async function onRequestGet6(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  const { searchParams } = new URL(request.url);
  let id = searchParams.get("id");
  if (id == null)
    return new Response(JSON.stringify({ error: "no property id" }), { status: 400 });
  const property = context.env.DB.prepare(`SELECT property.name,property.address_1,property.address_2,property.address_3,property.address_4,property.address_5,property.address_6,property.location,property.propertyType,property.state,property.description,property.internationalCost,property.internationalCurrency,property.id,property.area,property.bedrooms,property.bathrooms,property.garage,property.tranches,property.tranchesSold,property.tranchePrice from property where property.id = ${id}`);
  const propertyResult = await property.first();
  const amenities = context.env.DB.prepare(`SELECT property_amenities.name from property_amenities where property_amenities.propertyId = ${id}`);
  const amenitiesResults = await amenities.all();
  const images = context.env.DB.prepare(`SELECT property_images.url from property_images where property_images.propertyId = ${id}`);
  const imagesResults = await images.all();
  propertyResult.amenities = amenitiesResults.results;
  propertyResult.images = imagesResults.results;
  return new Response(JSON.stringify(propertyResult), { status: 200, headers: {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Max-Age": "86400"
  } });
}
async function onRequestPost3(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  const { searchParams } = new URL(request.url);
  let tranches = searchParams.get("tranches");
  let email = searchParams.get("email");
  let id = searchParams.get("id");
  console.log(email);
  const info = await context.env.DB.prepare("insert into property_leads (propertyId,email,tranchesRequested) VALUES (?1,?2,?3)").bind(id, email, tranches).run();
  return new Response(JSON.stringify({ "message": "ok" }), { status: 200, headers: {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Max-Age": "86400"
  } });
}
var init_crowdfund = __esm({
  "api/properties/crowdfund.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
  }
});

// api/properties/distributions.js
async function onRequestGet7(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  const { searchParams } = new URL(request.url);
  let id = searchParams.get("id");
  if (id == null)
    return new Response(JSON.stringify({ error: "no property id" }), { status: 400 });
  const costs = context.env.DB.prepare(`SELECT SUM(amountInternational) as total from rental_cost where propertyId = '${id}'`);
  const costResults = await costs.first();
  const payments = context.env.DB.prepare(`SELECT SUM(amountInternational) as total from rental_payment where propertyId = '${id}'`);
  const paymentResults = await payments.first();
  const dist = context.env.DB.prepare(`SELECT SUM(amountInternational) as total from property_distribution where propertyId = '${id}'`);
  const distResults = await dist.first();
  const token = context.env.DB.prepare(`SELECT * from property_token where propertyId = ${id} and isDeleted = 0`);
  const tokenResult = await token.first();
  const owners = context.env.DB.prepare(`SELECT property_owner.id,property_owner.tokenAmount,user.name,user.email,user.cryptoAddress from property_owner LEFT JOIN user ON property_owner.userId = user.id where property_owner.propertyTokenId = ${tokenResult.id}`);
  const ownersResult = await owners.all();
  let totalLeft = (paymentResults.total, +costResults.total) - distResults.total;
  let result = { "totalCosts": costResults.total, "totalPayments": paymentResults.total, "totalDistributions": distResults.total, "totalLeft": totalLeft, "token": tokenResult, "owners": ownersResult.results };
  return new Response(JSON.stringify(result), { status: 200 });
}
var init_distributions = __esm({
  "api/properties/distributions.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
  }
});

// api/properties/report.js
async function onRequestGet8(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  let result = {};
  const { searchParams } = new URL(request.url);
  let id = searchParams.get("id");
  if (id == null)
    return new Response(JSON.stringify({ error: "no property id" }), { status: 400 });
  const property = context.env.DB.prepare(`SELECT * from property where id = ${id}`);
  const propertyresult = await property.first();
  if (propertyresult == void 0)
    return new Response(JSON.stringify({ error: "no property found with that id" }), { status: 400 });
  const token = context.env.DB.prepare(`SELECT * from property_token where propertyId = ${id}`);
  const tokenresult = await token.first();
  console.log(tokenresult);
  if (tokenresult != void 0) {
    const owners = context.env.DB.prepare(`SELECT property_owner.id,property_owner.tokenAmount,user.name,user.email from property_owner LEFT JOIN user ON property_owner.userId = user.id where property_owner.propertyTokenId = ${tokenresult.id}`);
    const ownersresults = await owners.all();
    const distributions = context.env.DB.prepare(`SELECT * from property_distribution where propertyId = ${id}`);
    const distributionsresults = await distributions.all();
    result.owners = ownersresults.results;
    result.distributions = distributionsresults.results;
  } else {
    result.owners = {};
    result.distributions = {};
  }
  const agreement = context.env.DB.prepare(`SELECT * from rental_agreement where propertyId = ${id}`);
  const agreementresults = await agreement.all();
  const costs = context.env.DB.prepare(`SELECT * from rental_cost where propertyId = ${id}`);
  const costsresults = await costs.all();
  const payments = context.env.DB.prepare(`SELECT * from rental_payment where propertyId = ${id}`);
  const paymentsresults = await payments.all();
  result.property = propertyresult;
  result.token = tokenresult;
  result.agreements = agreementresults.results;
  result.costs = costsresults.results;
  result.payments = paymentsresults.results;
  return new Response(JSON.stringify(result), { status: 200 });
}
var init_report = __esm({
  "api/properties/report.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
  }
});

// api/settings.js
async function onRequestGet9(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  let details = await decodeJwt5(request.headers, env.SECRET);
  const KV = context.env.kvdata;
  let user = await KV.get("user" + details.payload.username);
  user = JSON.parse(user);
  let pData = await KV.get("settings" + user.user.secret);
  if (pData != null)
    return new Response(pData, { status: 200 });
  else
    return new Response(JSON.stringify({ error: "Settings not found" }), { status: 400 });
}
async function onRequestPut2(context) {
  const {
    request,
    // same as existing Worker API
    env,
    // same as existing Worker API
    params,
    // if filename includes [id] or [[path]]
    waitUntil,
    // same as ctx.waitUntil in existing Worker API
    next,
    // used for middleware or to fetch assets
    data
    // arbitrary space for passing data between middlewares
  } = context;
  try {
    contentType = request.headers.get("content-type");
    if (contentType != null) {
      payLoad = await request.json();
      let details = await decodeJwt5(request.headers, env.SECRET);
      const KV = context.env.kvdata;
      let user = await KV.get("user" + details.payload.username);
      user = JSON.parse(user);
      let theItem = settingsSchema;
      theItem = JSON.parse(theItem);
      if (theItem != null) {
        if (payLoad.companyname != void 0)
          theItem.companyname = payLoad.companyname;
        let user2 = await KV.get("user" + details.payload.username);
        user2 = JSON.parse(user2);
        await KV.delete("settings" + user2.user.secret);
        await KV.put("settings" + user2.user.secret, JSON.stringify(theItem));
        return new Response(JSON.stringify({ message: "Settings updated", data: JSON.stringify(theItem) }), { status: 200 });
      } else
        return new Response(JSON.stringify({ error: "Settings not found" }), { status: 400 });
    }
  } catch (error) {
    console.log(error);
    return new Response(error, { status: 200 });
  }
}
var payLoad, contentType, settingsSchema, jwt6, decodeJwt5;
var init_settings = __esm({
  "api/settings.js"() {
    init_functionsRoutes_0_9766584339725748();
    init_checked_fetch();
    init_modules_watch_stub();
    settingsSchema = '{"companyname":""}';
    jwt6 = require_cloudflare_worker_jwt();
    decodeJwt5 = async (req, secret) => {
      let bearer = req.get("authorization");
      bearer = bearer.replace("Bearer ", "");
      let details = await jwt6.decode(bearer, secret);
      return details;
    };
  }
});

// ../.wrangler/tmp/pages-Q2Ib7C/functionsRoutes-0.9766584339725748.mjs
var routes;
var init_functionsRoutes_0_9766584339725748 = __esm({
  "../.wrangler/tmp/pages-Q2Ib7C/functionsRoutes-0.9766584339725748.mjs"() {
    init_account();
    init_email();
    init_image();
    init_lookUp();
    init_schema();
    init_table();
    init_table();
    init_table();
    init_table();
    init_crowdfund();
    init_crowdfund();
    init_distributions();
    init_report();
    init_settings();
    init_settings();
    routes = [
      {
        routePath: "/api/admin/account",
        mountPath: "/api/admin",
        method: "POST",
        middlewares: [],
        modules: [onRequestPost]
      },
      {
        routePath: "/api/admin/email",
        mountPath: "/api/admin",
        method: "GET",
        middlewares: [],
        modules: [onRequestGet]
      },
      {
        routePath: "/api/admin/image",
        mountPath: "/api/admin",
        method: "GET",
        middlewares: [],
        modules: [onRequestGet2]
      },
      {
        routePath: "/api/database/lookUp",
        mountPath: "/api/database",
        method: "GET",
        middlewares: [],
        modules: [onRequestGet3]
      },
      {
        routePath: "/api/database/schema",
        mountPath: "/api/database",
        method: "GET",
        middlewares: [],
        modules: [onRequestGet4]
      },
      {
        routePath: "/api/database/table",
        mountPath: "/api/database",
        method: "DELETE",
        middlewares: [],
        modules: [onRequestDelete]
      },
      {
        routePath: "/api/database/table",
        mountPath: "/api/database",
        method: "GET",
        middlewares: [],
        modules: [onRequestGet5]
      },
      {
        routePath: "/api/database/table",
        mountPath: "/api/database",
        method: "POST",
        middlewares: [],
        modules: [onRequestPost2]
      },
      {
        routePath: "/api/database/table",
        mountPath: "/api/database",
        method: "PUT",
        middlewares: [],
        modules: [onRequestPut]
      },
      {
        routePath: "/api/properties/crowdfund",
        mountPath: "/api/properties",
        method: "GET",
        middlewares: [],
        modules: [onRequestGet6]
      },
      {
        routePath: "/api/properties/crowdfund",
        mountPath: "/api/properties",
        method: "POST",
        middlewares: [],
        modules: [onRequestPost3]
      },
      {
        routePath: "/api/properties/distributions",
        mountPath: "/api/properties",
        method: "GET",
        middlewares: [],
        modules: [onRequestGet7]
      },
      {
        routePath: "/api/properties/report",
        mountPath: "/api/properties",
        method: "GET",
        middlewares: [],
        modules: [onRequestGet8]
      },
      {
        routePath: "/api/settings",
        mountPath: "/api",
        method: "GET",
        middlewares: [],
        modules: [onRequestGet9]
      },
      {
        routePath: "/api/settings",
        mountPath: "/api",
        method: "PUT",
        middlewares: [],
        modules: [onRequestPut2]
      }
    ];
  }
});

// ../.wrangler/tmp/bundle-r7CdKT/middleware-loader.entry.ts
init_functionsRoutes_0_9766584339725748();
init_checked_fetch();
init_modules_watch_stub();

// ../../../../../../../../usr/local/lib/node_modules/wrangler/templates/middleware/common.ts
init_functionsRoutes_0_9766584339725748();
init_checked_fetch();
init_modules_watch_stub();
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}

// ../.wrangler/tmp/bundle-r7CdKT/middleware-insertion-facade.js
init_functionsRoutes_0_9766584339725748();
init_checked_fetch();
init_modules_watch_stub();

// ../../../../../../../../usr/local/lib/node_modules/wrangler/templates/pages-template-worker.ts
init_functionsRoutes_0_9766584339725748();
init_checked_fetch();
init_modules_watch_stub();

// ../../../../../../../../usr/local/lib/node_modules/path-to-regexp/dist.es2015/index.js
init_functionsRoutes_0_9766584339725748();
init_checked_fetch();
init_modules_watch_stub();
function lexer(str) {
  var tokens = [];
  var i = 0;
  while (i < str.length) {
    var char = str[i];
    if (char === "*" || char === "+" || char === "?") {
      tokens.push({ type: "MODIFIER", index: i, value: str[i++] });
      continue;
    }
    if (char === "\\") {
      tokens.push({ type: "ESCAPED_CHAR", index: i++, value: str[i++] });
      continue;
    }
    if (char === "{") {
      tokens.push({ type: "OPEN", index: i, value: str[i++] });
      continue;
    }
    if (char === "}") {
      tokens.push({ type: "CLOSE", index: i, value: str[i++] });
      continue;
    }
    if (char === ":") {
      var name = "";
      var j = i + 1;
      while (j < str.length) {
        var code = str.charCodeAt(j);
        if (
          // `0-9`
          code >= 48 && code <= 57 || // `A-Z`
          code >= 65 && code <= 90 || // `a-z`
          code >= 97 && code <= 122 || // `_`
          code === 95
        ) {
          name += str[j++];
          continue;
        }
        break;
      }
      if (!name)
        throw new TypeError("Missing parameter name at ".concat(i));
      tokens.push({ type: "NAME", index: i, value: name });
      i = j;
      continue;
    }
    if (char === "(") {
      var count = 1;
      var pattern = "";
      var j = i + 1;
      if (str[j] === "?") {
        throw new TypeError('Pattern cannot start with "?" at '.concat(j));
      }
      while (j < str.length) {
        if (str[j] === "\\") {
          pattern += str[j++] + str[j++];
          continue;
        }
        if (str[j] === ")") {
          count--;
          if (count === 0) {
            j++;
            break;
          }
        } else if (str[j] === "(") {
          count++;
          if (str[j + 1] !== "?") {
            throw new TypeError("Capturing groups are not allowed at ".concat(j));
          }
        }
        pattern += str[j++];
      }
      if (count)
        throw new TypeError("Unbalanced pattern at ".concat(i));
      if (!pattern)
        throw new TypeError("Missing pattern at ".concat(i));
      tokens.push({ type: "PATTERN", index: i, value: pattern });
      i = j;
      continue;
    }
    tokens.push({ type: "CHAR", index: i, value: str[i++] });
  }
  tokens.push({ type: "END", index: i, value: "" });
  return tokens;
}
function parse2(str, options) {
  if (options === void 0) {
    options = {};
  }
  var tokens = lexer(str);
  var _a = options.prefixes, prefixes = _a === void 0 ? "./" : _a;
  var defaultPattern = "[^".concat(escapeString(options.delimiter || "/#?"), "]+?");
  var result = [];
  var key = 0;
  var i = 0;
  var path = "";
  var tryConsume = function(type) {
    if (i < tokens.length && tokens[i].type === type)
      return tokens[i++].value;
  };
  var mustConsume = function(type) {
    var value2 = tryConsume(type);
    if (value2 !== void 0)
      return value2;
    var _a2 = tokens[i], nextType = _a2.type, index = _a2.index;
    throw new TypeError("Unexpected ".concat(nextType, " at ").concat(index, ", expected ").concat(type));
  };
  var consumeText = function() {
    var result2 = "";
    var value2;
    while (value2 = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")) {
      result2 += value2;
    }
    return result2;
  };
  while (i < tokens.length) {
    var char = tryConsume("CHAR");
    var name = tryConsume("NAME");
    var pattern = tryConsume("PATTERN");
    if (name || pattern) {
      var prefix = char || "";
      if (prefixes.indexOf(prefix) === -1) {
        path += prefix;
        prefix = "";
      }
      if (path) {
        result.push(path);
        path = "";
      }
      result.push({
        name: name || key++,
        prefix,
        suffix: "",
        pattern: pattern || defaultPattern,
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    var value = char || tryConsume("ESCAPED_CHAR");
    if (value) {
      path += value;
      continue;
    }
    if (path) {
      result.push(path);
      path = "";
    }
    var open = tryConsume("OPEN");
    if (open) {
      var prefix = consumeText();
      var name_1 = tryConsume("NAME") || "";
      var pattern_1 = tryConsume("PATTERN") || "";
      var suffix = consumeText();
      mustConsume("CLOSE");
      result.push({
        name: name_1 || (pattern_1 ? key++ : ""),
        pattern: name_1 && !pattern_1 ? defaultPattern : pattern_1,
        prefix,
        suffix,
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    mustConsume("END");
  }
  return result;
}
function match(str, options) {
  var keys = [];
  var re = pathToRegexp(str, keys, options);
  return regexpToFunction(re, keys, options);
}
function regexpToFunction(re, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.decode, decode = _a === void 0 ? function(x) {
    return x;
  } : _a;
  return function(pathname) {
    var m = re.exec(pathname);
    if (!m)
      return false;
    var path = m[0], index = m.index;
    var params = /* @__PURE__ */ Object.create(null);
    var _loop_1 = function(i2) {
      if (m[i2] === void 0)
        return "continue";
      var key = keys[i2 - 1];
      if (key.modifier === "*" || key.modifier === "+") {
        params[key.name] = m[i2].split(key.prefix + key.suffix).map(function(value) {
          return decode(value, key);
        });
      } else {
        params[key.name] = decode(m[i2], key);
      }
    };
    for (var i = 1; i < m.length; i++) {
      _loop_1(i);
    }
    return { path, index, params };
  };
}
function escapeString(str) {
  return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
function flags(options) {
  return options && options.sensitive ? "" : "i";
}
function regexpToRegexp(path, keys) {
  if (!keys)
    return path;
  var groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
  var index = 0;
  var execResult = groupsRegex.exec(path.source);
  while (execResult) {
    keys.push({
      // Use parenthesized substring match if available, index otherwise
      name: execResult[1] || index++,
      prefix: "",
      suffix: "",
      modifier: "",
      pattern: ""
    });
    execResult = groupsRegex.exec(path.source);
  }
  return path;
}
function arrayToRegexp(paths, keys, options) {
  var parts = paths.map(function(path) {
    return pathToRegexp(path, keys, options).source;
  });
  return new RegExp("(?:".concat(parts.join("|"), ")"), flags(options));
}
function stringToRegexp(path, keys, options) {
  return tokensToRegexp(parse2(path, options), keys, options);
}
function tokensToRegexp(tokens, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.strict, strict = _a === void 0 ? false : _a, _b = options.start, start = _b === void 0 ? true : _b, _c = options.end, end = _c === void 0 ? true : _c, _d = options.encode, encode = _d === void 0 ? function(x) {
    return x;
  } : _d, _e = options.delimiter, delimiter = _e === void 0 ? "/#?" : _e, _f = options.endsWith, endsWith = _f === void 0 ? "" : _f;
  var endsWithRe = "[".concat(escapeString(endsWith), "]|$");
  var delimiterRe = "[".concat(escapeString(delimiter), "]");
  var route = start ? "^" : "";
  for (var _i = 0, tokens_1 = tokens; _i < tokens_1.length; _i++) {
    var token = tokens_1[_i];
    if (typeof token === "string") {
      route += escapeString(encode(token));
    } else {
      var prefix = escapeString(encode(token.prefix));
      var suffix = escapeString(encode(token.suffix));
      if (token.pattern) {
        if (keys)
          keys.push(token);
        if (prefix || suffix) {
          if (token.modifier === "+" || token.modifier === "*") {
            var mod = token.modifier === "*" ? "?" : "";
            route += "(?:".concat(prefix, "((?:").concat(token.pattern, ")(?:").concat(suffix).concat(prefix, "(?:").concat(token.pattern, "))*)").concat(suffix, ")").concat(mod);
          } else {
            route += "(?:".concat(prefix, "(").concat(token.pattern, ")").concat(suffix, ")").concat(token.modifier);
          }
        } else {
          if (token.modifier === "+" || token.modifier === "*") {
            route += "((?:".concat(token.pattern, ")").concat(token.modifier, ")");
          } else {
            route += "(".concat(token.pattern, ")").concat(token.modifier);
          }
        }
      } else {
        route += "(?:".concat(prefix).concat(suffix, ")").concat(token.modifier);
      }
    }
  }
  if (end) {
    if (!strict)
      route += "".concat(delimiterRe, "?");
    route += !options.endsWith ? "$" : "(?=".concat(endsWithRe, ")");
  } else {
    var endToken = tokens[tokens.length - 1];
    var isEndDelimited = typeof endToken === "string" ? delimiterRe.indexOf(endToken[endToken.length - 1]) > -1 : endToken === void 0;
    if (!strict) {
      route += "(?:".concat(delimiterRe, "(?=").concat(endsWithRe, "))?");
    }
    if (!isEndDelimited) {
      route += "(?=".concat(delimiterRe, "|").concat(endsWithRe, ")");
    }
  }
  return new RegExp(route, flags(options));
}
function pathToRegexp(path, keys, options) {
  if (path instanceof RegExp)
    return regexpToRegexp(path, keys);
  if (Array.isArray(path))
    return arrayToRegexp(path, keys, options);
  return stringToRegexp(path, keys, options);
}

// ../../../../../../../../usr/local/lib/node_modules/wrangler/templates/pages-template-worker.ts
var escapeRegex = /[.+?^${}()|[\]\\]/g;
function* executeRequest(request) {
  const requestPath = new URL(request.url).pathname;
  for (const route of [...routes].reverse()) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath);
    const mountMatchResult = mountMatcher(requestPath);
    if (matchResult && mountMatchResult) {
      for (const handler of route.middlewares.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: mountMatchResult.path
        };
      }
    }
  }
  for (const route of routes) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: true
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath);
    const mountMatchResult = mountMatcher(requestPath);
    if (matchResult && mountMatchResult && route.modules.length) {
      for (const handler of route.modules.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: matchResult.path
        };
      }
      break;
    }
  }
}
var pages_template_worker_default = {
  async fetch(originalRequest, env, workerContext) {
    let request = originalRequest;
    const handlerIterator = executeRequest(request);
    let data = {};
    let isFailOpen = false;
    const next = async (input, init) => {
      if (input !== void 0) {
        let url = input;
        if (typeof input === "string") {
          url = new URL(input, request.url).toString();
        }
        request = new Request(url, init);
      }
      const result = handlerIterator.next();
      if (result.done === false) {
        const { handler, params, path } = result.value;
        const context = {
          request: new Request(request.clone()),
          functionPath: path,
          next,
          params,
          get data() {
            return data;
          },
          set data(value) {
            if (typeof value !== "object" || value === null) {
              throw new Error("context.data must be an object");
            }
            data = value;
          },
          env,
          waitUntil: workerContext.waitUntil.bind(workerContext),
          passThroughOnException: () => {
            isFailOpen = true;
          }
        };
        const response = await handler(context);
        if (!(response instanceof Response)) {
          throw new Error("Your Pages function should return a Response");
        }
        return cloneResponse(response);
      } else if ("ASSETS") {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      } else {
        const response = await fetch(request);
        return cloneResponse(response);
      }
    };
    try {
      return await next();
    } catch (error) {
      if (isFailOpen) {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      }
      throw error;
    }
  }
};
var cloneResponse = (response) => (
  // https://fetch.spec.whatwg.org/#null-body-status
  new Response(
    [101, 204, 205, 304].includes(response.status) ? null : response.body,
    response
  )
);

// ../../../../../../../../usr/local/lib/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
init_functionsRoutes_0_9766584339725748();
init_checked_fetch();
init_modules_watch_stub();
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
var jsonError = async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
};
var middleware_miniflare3_json_error_default = jsonError;
var wrap = void 0;

// ../.wrangler/tmp/bundle-r7CdKT/middleware-insertion-facade.js
var envWrappers = [wrap].filter(Boolean);
var facade = {
  ...pages_template_worker_default,
  envWrappers,
  middleware: [
    middleware_miniflare3_json_error_default,
    ...pages_template_worker_default.middleware ? pages_template_worker_default.middleware : []
  ].filter(Boolean)
};
var middleware_insertion_facade_default = facade;

// ../.wrangler/tmp/bundle-r7CdKT/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof __Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
var __facade_modules_fetch__ = function(request, env, ctx) {
  if (middleware_insertion_facade_default.fetch === void 0)
    throw new Error("Handler does not export a fetch() function.");
  return middleware_insertion_facade_default.fetch(request, env, ctx);
};
function getMaskedEnv(rawEnv) {
  let env = rawEnv;
  if (middleware_insertion_facade_default.envWrappers && middleware_insertion_facade_default.envWrappers.length > 0) {
    for (const wrapFn of middleware_insertion_facade_default.envWrappers) {
      env = wrapFn(env);
    }
  }
  return env;
}
var registeredMiddleware = false;
var facade2 = {
  ...middleware_insertion_facade_default.tail && {
    tail: maskHandlerEnv(middleware_insertion_facade_default.tail)
  },
  ...middleware_insertion_facade_default.trace && {
    trace: maskHandlerEnv(middleware_insertion_facade_default.trace)
  },
  ...middleware_insertion_facade_default.scheduled && {
    scheduled: maskHandlerEnv(middleware_insertion_facade_default.scheduled)
  },
  ...middleware_insertion_facade_default.queue && {
    queue: maskHandlerEnv(middleware_insertion_facade_default.queue)
  },
  ...middleware_insertion_facade_default.test && {
    test: maskHandlerEnv(middleware_insertion_facade_default.test)
  },
  ...middleware_insertion_facade_default.email && {
    email: maskHandlerEnv(middleware_insertion_facade_default.email)
  },
  fetch(request, rawEnv, ctx) {
    const env = getMaskedEnv(rawEnv);
    if (middleware_insertion_facade_default.middleware && middleware_insertion_facade_default.middleware.length > 0) {
      if (!registeredMiddleware) {
        registeredMiddleware = true;
        for (const middleware of middleware_insertion_facade_default.middleware) {
          __facade_register__(middleware);
        }
      }
      const __facade_modules_dispatch__ = function(type, init) {
        if (type === "scheduled" && middleware_insertion_facade_default.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return middleware_insertion_facade_default.scheduled(controller, env, ctx);
        }
      };
      return __facade_invoke__(
        request,
        env,
        ctx,
        __facade_modules_dispatch__,
        __facade_modules_fetch__
      );
    } else {
      return __facade_modules_fetch__(request, env, ctx);
    }
  }
};
function maskHandlerEnv(handler) {
  return (data, env, ctx) => handler(data, getMaskedEnv(env), ctx);
}
var middleware_loader_entry_default = facade2;
export {
  middleware_loader_entry_default as default
};
//# sourceMappingURL=functionsWorker-0.967255199145614.mjs.map

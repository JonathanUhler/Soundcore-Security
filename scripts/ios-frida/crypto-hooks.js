'use strict';
/*
 * crypto-hooks.js  --  Log the HMAC, SHA, and ECDH primitives, and give a template
 * for the app's own signing methods.
 *
 *   frida -U Gadget -l scripts/ios-frida/crypto-hooks.js
 *
 * The recovered scheme is an ECDH P-256 exchange feeding a two-tier HMAC-SHA256
 * signer (see anker-signing-scheme-recovered). On iOS the primitives are most
 * likely CommonCrypto (CCHmac family, CC_SHA256) or the bundled OpenSSL
 * (HMAC, ECDH_compute_key). Hooking them exposes the raw keys, messages, and the
 * derived ECDH shared secret, which is what a proxy cannot show.
 *
 * Run recon.js first. If these primitives show nothing, the crypto is in Swift
 * CryptoKit or an app wrapper class. Use hookObjc() at the bottom with the class
 * and selector names recon reported.
 */

function bytesHex(ptr, len) {
  if (ptr === null || ptr.isNull() || len <= 0) return '';
  len = Math.min(len, 1024);
  try {
    var u = new Uint8Array(ptr.readByteArray(len));
    var s = '';
    for (var i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
    return s;
  } catch (e) { return '<unreadable ' + len + '>'; }
}

// CommonCrypto HMAC algorithm ids and their output lengths.
var HMAC_LEN = { 0: 20, 1: 16, 2: 32, 3: 48, 4: 64, 5: 28 };
var HMAC_NAME = { 0: 'SHA1', 1: 'MD5', 2: 'SHA256', 3: 'SHA384', 4: 'SHA512', 5: 'SHA224' };

/* Resolve an export by module name or globally, across Frida 16 and 17. */
function findExport(mod, name) {
  try {
    if (mod) {
      var m = Process.findModuleByName(mod);
      if (m === null) return null;
      if (typeof m.findExportByName === 'function') return m.findExportByName(name);
      return Module.findExportByName(mod, name);
    }
    if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(name);
    if (typeof Module.getGlobalExportByName === 'function') {
      try { return Module.getGlobalExportByName(name); } catch (e) { return null; }
    }
    return Module.findExportByName(null, name);
  } catch (e) { return null; }
}

function attach(sym, mod, handlers) {
  var p = findExport(mod, sym);
  if (p === null || p.isNull()) return false;
  Interceptor.attach(p, handlers);
  console.log('[crypto] hooked ' + sym + (mod ? ' in ' + mod : ''));
  return true;
}

/* One-shot HMAC. CCHmac(algo, key, keyLen, data, dataLen, macOut). */
attach('CCHmac', null, {
  onEnter: function (args) {
    this.algo = args[0].toInt32();
    this.keyLen = args[2].toInt32();
    this.key = bytesHex(args[1], this.keyLen);
    this.dataLen = args[4].toInt32();
    this.data = bytesHex(args[3], this.dataLen);
    this.mac = args[5];
  },
  onLeave: function () {
    var n = HMAC_LEN[this.algo] || 32;
    console.log('\n[CCHmac ' + (HMAC_NAME[this.algo] || this.algo) + ']' +
      '\n  key(' + this.keyLen + ')= ' + this.key +
      '\n  msg(' + this.dataLen + ')= ' + this.data +
      '\n  mac= ' + bytesHex(this.mac, n));
  }
});

/* Streaming HMAC, keyed by context pointer. */
var hmacCtx = {};
attach('CCHmacInit', null, {
  onEnter: function (args) {
    var ctx = args[0].toString();
    hmacCtx[ctx] = { algo: args[1].toInt32(), key: bytesHex(args[2], args[3].toInt32()),
                     keyLen: args[3].toInt32(), msg: '' };
  }
});
attach('CCHmacUpdate', null, {
  onEnter: function (args) {
    var c = hmacCtx[args[0].toString()];
    if (c) c.msg += bytesHex(args[1], args[2].toInt32());
  }
});
attach('CCHmacFinal', null, {
  onEnter: function (args) { this.ctx = args[0].toString(); this.mac = args[1]; },
  onLeave: function () {
    var c = hmacCtx[this.ctx];
    if (!c) return;
    var n = HMAC_LEN[c.algo] || 32;
    console.log('\n[CCHmac* ' + (HMAC_NAME[c.algo] || c.algo) + ' streamed]' +
      '\n  key(' + c.keyLen + ')= ' + c.key +
      '\n  msg= ' + c.msg +
      '\n  mac= ' + bytesHex(this.mac, n));
    delete hmacCtx[this.ctx];
  }
});

/* ECDH shared secret. ECDH_compute_key(out, outlen, pub, ecdh, kdf) -> len. */
if (!attach('ECDH_compute_key', 'OpenSSL', {
  onEnter: function (args) { this.out = args[0]; this.outlen = args[1].toInt32(); },
  onLeave: function (retval) {
    var n = retval.toInt32();
    console.log('\n[ECDH_compute_key] shared secret(' + n + ')= ' +
      bytesHex(this.out, n > 0 ? n : this.outlen));
  }
})) {
  // Try the global namespace in case OpenSSL exports are flattened.
  attach('ECDH_compute_key', null, {
    onEnter: function (args) { this.out = args[0]; this.outlen = args[1].toInt32(); },
    onLeave: function (retval) {
      var n = retval.toInt32();
      console.log('\n[ECDH_compute_key] shared secret(' + n + ')= ' +
        bytesHex(this.out, n > 0 ? n : this.outlen));
    }
  });
}

/* OpenSSL one-shot HMAC, if used instead of CommonCrypto.
 * HMAC(evp_md, key, keyLen, data, dataLen, md_out, md_len_out). */
attach('HMAC', 'OpenSSL', {
  onEnter: function (args) {
    this.key = bytesHex(args[1], args[2].toInt32());
    this.keyLen = args[2].toInt32();
    this.data = bytesHex(args[3], args[4].toInt32());
    this.dataLen = args[4].toInt32();
    this.md = args[5];
    this.mdLenOut = args[6];
  },
  onLeave: function () {
    var n = 32;
    try { if (!this.mdLenOut.isNull()) n = this.mdLenOut.readU32(); } catch (e) {}
    console.log('\n[OpenSSL HMAC]' +
      '\n  key(' + this.keyLen + ')= ' + this.key +
      '\n  msg(' + this.dataLen + ')= ' + this.data +
      '\n  mac= ' + bytesHex(this.md, n));
  }
});

/*
 * Template for the app's own signing methods, once recon names the classes.
 * Example candidates from the Android side were KeyExchangeManager.executeKeyExchange,
 * HeaderBuilder setters, and CommonHeadersInterceptor.intercept. Fill in the real
 * ObjC class and selector and uncomment.
 */
function hookObjc(className, selector) {
  if (!ObjC.available || !(className in ObjC.classes)) {
    console.log('[crypto] class not present: ' + className);
    return;
  }
  var m = ObjC.classes[className][selector];
  if (!m) { console.log('[crypto] selector not found: ' + selector); return; }
  Interceptor.attach(m.implementation, {
    onEnter: function (args) {
      console.log('\n[objc] ' + className + ' ' + selector);
      // args[0]=self, args[1]=selector, args[2..]=params
    },
    onLeave: function (retval) {
      try { console.log('  ret: ' + new ObjC.Object(retval).toString()); } catch (e) {}
    }
  });
  console.log('[crypto] hooked ' + className + ' ' + selector);
}

// hookObjc('KeyExchangeManager', '- executeKeyExchange');
// hookObjc('CommonHeadersInterceptor', '- intercept:');

console.log('[crypto] primitive hooks installed. Trigger login and a check for update.');

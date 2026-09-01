'use strict';
/*
 * recon.js  --  Confirm the Frida Gadget loaded and map the crypto surface.
 *
 * Run first, before the capture hooks:
 *   frida -U Gadget -l scripts/ios-frida/recon.js
 *
 * It prints the process facts, the loaded modules of interest, the ObjC classes
 * whose names suggest signing or OTA logic, and the exported crypto symbols in
 * OpenSSL and CommonCrypto. Use the class and symbol names it reports to fill in
 * the app-specific hooks in crypto-hooks.js.
 */

function line(s) { console.log(s); }
function hdr(s) { console.log('\n==================== ' + s + ' ===================='); }

/* Resolve a global export across Frida 16 and 17 API differences. */
function findExport(name) {
  try {
    if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(name);
    if (typeof Module.getGlobalExportByName === 'function') {
      try { return Module.getGlobalExportByName(name); } catch (e) { return null; }
    }
    return Module.findExportByName(null, name);
  } catch (e) { return null; }
}

hdr('PROCESS');
line('frida       : ' + Frida.version);
line('pid / arch  : ' + Process.id + ' / ' + Process.arch);
line('page size   : ' + Process.pageSize);
line('objc avail  : ' + ObjC.available);

/* Modules of interest. A decrypted App Store build ships these as frameworks. */
hdr('MODULES OF INTEREST');
var MODNEEDLES = ['SoundCore', 'App.framework', 'Flutter', 'OpenSSL', 'commonCrypto',
                  'CommonCrypto', 'Alamofire', 'Moya', 'Starscream', 'boringssl', 'Security'];
Process.enumerateModules().forEach(function (m) {
  for (var i = 0; i < MODNEEDLES.length; i++) {
    if (m.name.indexOf(MODNEEDLES[i]) !== -1 || m.path.indexOf(MODNEEDLES[i]) !== -1) {
      line('  ' + m.name + '  @ ' + m.base + '  (' + m.size + ' bytes)');
      break;
    }
  }
});

/* ObjC classes whose names hint at the signing, header, or OTA logic. */
hdr('CANDIDATE OBJC CLASSES');
if (ObjC.available) {
  var CLASSRE = /(KeyExchange|Header|Sign|Crypto|Cipher|HMAC|ECDH|KeyPair|OTA|Firmware|Upgrade|Interceptor|Network|Request|ApiSign|Token)/i;
  var hits = [];
  for (var name in ObjC.classes) {
    if (CLASSRE.test(name)) hits.push(name);
  }
  hits.sort();
  line('  ' + hits.length + ' matches');
  hits.forEach(function (n) { line('    ' + n); });
} else {
  line('  ObjC runtime not available');
}

/* Exported crypto symbols. These are the primitive-level hook targets. */
function dumpExports(modName, re) {
  hdr('EXPORTS ' + modName + '  matching ' + re);
  var mod = Process.findModuleByName(modName);
  if (mod === null) {
    // try a path substring match
    Process.enumerateModules().forEach(function (m) {
      if (mod === null && m.name.indexOf(modName) !== -1) mod = m;
    });
  }
  if (mod === null) { line('  module not loaded'); return; }
  var n = 0;
  mod.enumerateExports().forEach(function (e) {
    if (re.test(e.name)) { line('    ' + e.name + '  @ ' + e.address); n++; }
  });
  if (n === 0) line('  no matching exports (symbols may be stripped)');
}

dumpExports('OpenSSL', /(HMAC|ECDH|EC_KEY|EC_POINT|SHA256|EVP_|PKEY|X25519|ECDSA)/);
dumpExports('libcommonCrypto.dylib', /(CCHmac|CC_SHA|CCCrypt|CCKeyDerivation)/);

/* CommonCrypto is usually reachable as a global export too. Confirm the key ones. */
hdr('GLOBAL CRYPTO EXPORTS (any module)');
['CCHmac', 'CCHmacInit', 'CCHmacUpdate', 'CCHmacFinal', 'CC_SHA256', 'CC_SHA256_Update',
 'ECDH_compute_key', 'HMAC', 'EVP_DigestSignFinal'].forEach(function (sym) {
  var p = findExport(sym);
  line('  ' + (p ? 'FOUND ' : 'absent') + '  ' + sym + (p ? '  @ ' + p : ''));
});

/* Cheap anti-debug awareness. Report whether the usual guards are even present. */
hdr('ANTI-DEBUG SURFACE');
['ptrace', 'sysctl', 'getppid'].forEach(function (sym) {
  var p = findExport(sym);
  line('  ' + (p ? 'present' : 'absent') + '  ' + sym);
});

line('\n[recon] done. Feed the class and symbol names above into crypto-hooks.js.');

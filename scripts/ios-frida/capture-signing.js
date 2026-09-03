'use strict';
/*
 * capture-signing.js  --  Grab the speaker-API signing credentials at runtime.
 *
 * The signing algorithm is recovered, but the credential VALUES (clientId,
 * clientSecret/localKey, presetKey) are injected from the Swift layer into the KMP
 * network config at runtime, not stored as static constants. The one call that
 * carries all three is initConfig, exposed to ObjC as
 *   -[<KMP config> doInitConfigClientId:clientSecret:presetKey:appName:...]
 * and the bootstrap signer is
 *   -[<KMP config> encryptByHMAC256ClientId:tsMsg:onceMsg:].
 *
 * We do NOT need the app to fully boot. We only need doInitConfig (or the setters,
 * or one encryptByHMAC256) to run once while these hooks are installed. That call
 * happens during startup, in a race with the anti-tamper kill. Load this together
 * with anti-tamper.js, which keeps the process limping long enough for the config
 * init to run:
 *
 *   frida -U -f com.oceanwing.SoundCore.G8AW4BQ7RV \
 *     -l scripts/ios-frida/anti-tamper.js \
 *     -l scripts/ios-frida/capture-signing.js
 *   (wait for "armed", type %resume, then read the [CAP] lines)
 *
 * Ghidra anchors (preferred base 0x100000000, runtime = mainModule.base + offset):
 *   0x2ee3508  -[.. doInitConfigClientId:clientSecret:presetKey:appName:..]
 *   0x2eee3bc  -[.. encryptByHMAC256ClientId:tsMsg:onceMsg:]
 * These are the ObjC bridge thunks whose args are NSStrings, easy to read.
 */

var OFF = {
  doInitConfig:     0x2ee3508,
  encryptByHMAC256: 0x2eee3bc
};

var mainModule = Process.mainModule || Process.enumerateModules()[0];
function rt(off) { return mainModule.base.add(off); }

function str(p) {
  try {
    if (p === null || p.isNull()) return '<null>';
    return new ObjC.Object(p).toString();
  } catch (e) {
    try { return p.readUtf8String(); } catch (e2) { return '<' + p + '>'; }
  }
}

var captured = { clientId: null, clientSecret: null, presetKey: null, appName: null };

/* THE prize: doInitConfig carries clientId, clientSecret, presetKey together. */
try {
  Interceptor.attach(rt(OFF.doInitConfig), {
    onEnter: function (args) {
      // (self, _cmd, clientId, clientSecret, presetKey, appName, whiteList, domainApi, ...)
      captured.clientId = str(args[2]);
      captured.clientSecret = str(args[3]);
      captured.presetKey = str(args[4]);
      captured.appName = str(args[5]);
      console.log('\n########## [CAP] doInitConfig ##########');
      console.log('  clientId     = ' + captured.clientId);
      console.log('  clientSecret = ' + captured.clientSecret + '   <-- bootstrap HMAC key');
      console.log('  presetKey    = ' + captured.presetKey);
      console.log('  appName      = ' + captured.appName);
      console.log('  domainApi    = ' + str(args[7]));
      console.log('########################################');
    }
  });
  console.log('[CAP] hooked doInitConfig @ ' + rt(OFF.doInitConfig));
} catch (e) { console.log('[CAP] doInitConfig hook failed: ' + e); }

/* The bootstrap signer: inputs (clientId, ts, once) and the resulting X-Signature.
 * Seeing this fire proves the signer ran and shows the exact signed inputs. */
try {
  Interceptor.attach(rt(OFF.encryptByHMAC256), {
    onEnter: function (args) {
      this.cid = str(args[2]); this.ts = str(args[3]); this.once = str(args[4]);
    },
    onLeave: function (retval) {
      console.log('\n[CAP] encryptByHMAC256  clientId=' + this.cid +
                  '  ts=' + this.ts + '  once=' + this.once + '  -> sig=' + str(retval));
    }
  });
  console.log('[CAP] hooked encryptByHMAC256 @ ' + rt(OFF.encryptByHMAC256));
} catch (e) { console.log('[CAP] encryptByHMAC256 hook failed: ' + e); }

/* NOTE: an ObjC ApiResolver scan was tried here and it crashed the agent during
 * load, before %resume. Enumerating the ObjC runtime forces class realization,
 * which runs +initialize/+load methods, and one of those is anti-tamper code that
 * kills the process. Do NOT enumerate the ObjC runtime. Hook only by fixed address.
 * The session signer and ECDH key getters can be added by address later if needed. */

console.log('\n[CAP] signing-capture hooks installed (address-only). Resume and watch for');
console.log('[CAP] doInitConfig. If nothing fires before it dies, initConfig runs after the kill.');
console.log('[CAP] if the app dies before it fires, the config init runs later than the kill,');
console.log('      and we need the app to survive further into startup.');

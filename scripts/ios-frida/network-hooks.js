'use strict';
/*
 * network-hooks.js  --  Capture TLS-decrypted HTTP(S) at the NSURLSession layer.
 *
 *   frida -U Gadget -l scripts/ios-frida/network-hooks.js
 *
 * Reading the NSURLRequest and the response objects inside the process gives the
 * plaintext regardless of certificate pinning, which is the point of using Frida
 * against the pinned speaker.eufylife.com host. The signing headers (gToken, sign,
 * nonce, timestamp, and the newer HMAC family) ride in the request headers, so the
 * request dump alone exposes them. The check-for-update response carries the
 * firmware file URL and md5.
 *
 * Requests are captured across every concrete NSURLSession subclass. Responses are
 * captured where a completion handler block is supplied. Alamofire uses the delegate
 * path instead, so if response bodies are missing, read them from crypto-hooks.js
 * output or from a parallel mitmproxy run, or extend this with the task-delegate
 * hooks noted at the bottom.
 */

var NSUTF8 = 4;

function dataToText(dataPtr) {
  if (dataPtr === null || dataPtr.isNull()) return '<null>';
  var data = new ObjC.Object(dataPtr);
  try {
    if (data.length() === 0) return '<empty>';
    var s = ObjC.classes.NSString.alloc().initWithData_encoding_(data, NSUTF8);
    if (s !== null && !s.isNull()) return s.toString();
  } catch (e) {}
  return '<binary ' + data.length() + ' bytes>';
}

function logRequest(reqPtr, tag) {
  try {
    var req = new ObjC.Object(reqPtr);
    var url = req.URL() && !req.URL().isNull() ? req.URL().absoluteString().toString() : '<no url>';
    var method = req.HTTPMethod() && !req.HTTPMethod().isNull() ? req.HTTPMethod().toString() : '?';
    console.log('\n===> [' + tag + '] ' + method + ' ' + url);
    var headers = req.allHTTPHeaderFields();
    if (headers && !headers.isNull()) {
      var keys = headers.allKeys();
      for (var i = 0; i < keys.count(); i++) {
        var k = keys.objectAtIndex_(i);
        console.log('     ' + k + ': ' + headers.objectForKey_(k));
      }
    }
    var body = req.HTTPBody();
    if (body && !body.isNull()) console.log('     body: ' + dataToText(body));
  } catch (e) {
    console.log('logRequest error: ' + e);
  }
}

function logResponse(tag, dataPtr, responsePtr, errorPtr) {
  try {
    var url = '<no url>';
    var status = '';
    if (responsePtr && !responsePtr.isNull()) {
      var resp = new ObjC.Object(responsePtr);
      if (resp.URL && resp.URL() && !resp.URL().isNull()) url = resp.URL().absoluteString().toString();
      if (resp.statusCode) status = ' [' + resp.statusCode() + ']';
    }
    console.log('\n<=== [' + tag + '] response' + status + ' ' + url);
    if (errorPtr && !errorPtr.isNull()) {
      console.log('     error: ' + new ObjC.Object(errorPtr).localizedDescription());
    }
    console.log('     body: ' + dataToText(dataPtr));
  } catch (e) {
    console.log('logResponse error: ' + e);
  }
}

if (!ObjC.available) {
  console.log('[network] ObjC runtime unavailable, cannot hook NSURLSession');
} else {
  var resolver = new ApiResolver('objc');

  /* Request plus response, completion-handler form. */
  ['-[* dataTaskWithRequest:completionHandler:]',
   '-[* uploadTaskWithRequest:fromData:completionHandler:]'].forEach(function (pattern) {
    resolver.enumerateMatches(pattern).forEach(function (m) {
      try {
        Interceptor.attach(m.address, {
          onEnter: function (args) {
            logRequest(args[2], 'task+cb');
            // completion handler is the last block argument
            var cbIndex = pattern.indexOf('fromData:') !== -1 ? 4 : 3;
            var cb = args[cbIndex];
            if (cb.isNull()) return;
            var block = new ObjC.Block(cb);
            var orig = block.implementation;
            block.implementation = function (data, response, error) {
              logResponse('task+cb', data, response, error);
              return orig(data, response, error);
            };
          }
        });
      } catch (e) { console.log('attach failed on ' + m.name + ': ' + e); }
    });
  });

  /* Request only, delegate form. Responses arrive via the task delegate. */
  ['-[* dataTaskWithRequest:]',
   '-[* uploadTaskWithRequest:fromData:]',
   '-[* downloadTaskWithRequest:]'].forEach(function (pattern) {
    resolver.enumerateMatches(pattern).forEach(function (m) {
      try {
        Interceptor.attach(m.address, {
          onEnter: function (args) { logRequest(args[2], 'task'); }
        });
      } catch (e) {}
    });
  });

  console.log('[network] NSURLSession hooks installed. Drive the app now.');
}

/*
 * If Alamofire response bodies are needed, add delegate hooks for the concrete
 * session delegate class named by recon, for example:
 *   -[<Delegate> URLSession:dataTask:didReceiveData:]
 *   -[<Delegate> URLSession:task:didCompleteWithError:]
 * Accumulate the NSData chunks per task and flush on completion.
 */

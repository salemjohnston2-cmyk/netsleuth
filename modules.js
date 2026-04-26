'use strict';

const FREE_MODULES = [
  'whois', 'subdomains', 'dns', 'ip',
  'headers', 'robots', 'emails',
  'sourcecode', 'endpoints', 'adminpanels',
  'backlinks', 'indexing'
];

const PREMIUM_MODULES = ['ports', 'deepsubs', 'traffic'];

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function safeFetch(url, options = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);
    return res;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
}

// ─── Modules ──────────────────────────────────────────────────────────────────

async function whois(domain) {
  const res = await safeFetch(`https://rdap.org/domain/${domain}`);
  const d = await res.json();
  const event = (action) => d.events?.find(e => e.eventAction === action)?.eventDate || null;
  const registrar = d.entities
    ?.find(e => e.roles?.includes('registrar'))
    ?.vcardArray?.[1]
    ?.find(v => v[0] === 'fn')?.[3] || null;
  return {
    registrar,
    created: event('registration'),
    updated: event('last changed'),
    expires: event('expiration'),
    status: d.status || [],
    nameservers: (d.nameservers || []).map(ns => ns.ldhName?.toLowerCase())
  };
}

async function subdomains(domain) {
  const res = await safeFetch(`https://crt.sh/?q=%.${domain}&output=json`, {}, 12000);
  const data = await res.json();
  const all = [...new Set(
    data.flatMap(c => c.name_value.split('\n'))
      .map(s => s.toLowerCase().trim())
      .filter(s => s.endsWith(`.${domain}`) && !s.includes('*'))
  )].sort();
  return {
    count: all.length,
    subdomains: all.slice(0, 60),
    truncated: all.length > 60,
    note: all.length > 60 ? `Showing 60 of ${all.length}. Upgrade to Pro for full list.` : null
  };
}

async function dns(domain) {
  const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];
  const settled = await Promise.allSettled(
    types.map(t =>
      safeFetch(`https://dns.google/resolve?name=${domain}&type=${t}`)
        .then(r => r.json())
        .then(d => ({ type: t, records: (d.Answer || []).map(a => a.data) }))
    )
  );
  const result = {};
  settled.forEach(r => {
    if (r.status === 'fulfilled' && r.value.records.length > 0) {
      result[r.value.type] = r.value.records;
    }
  });
  return result;
}

async function ip(domain) {
  const dnsRes = await safeFetch(`https://dns.google/resolve?name=${domain}&type=A`);
  const dnsData = await dnsRes.json();
  const ipAddr = dnsData.Answer?.[0]?.data;
  if (!ipAddr) return { error: 'Could not resolve IP address' };
  const geo = await safeFetch(
    `http://ip-api.com/json/${ipAddr}?fields=country,regionName,city,isp,org,as,reverse,hosting,proxy`
  ).then(r => r.json());
  return {
    ip: ipAddr,
    country: geo.country,
    region: geo.regionName,
    city: geo.city,
    isp: geo.isp,
    org: geo.org,
    asn: geo.as,
    reverse_dns: geo.reverse,
    is_hosting: geo.hosting,
    is_proxy: geo.proxy
  };
}

async function headers(domain) {
  const res = await safeFetch(`https://${domain}`, { method: 'HEAD', redirect: 'follow' });
  const watch = [
    'server', 'x-powered-by', 'x-frame-options', 'content-security-policy',
    'strict-transport-security', 'x-xss-protection', 'x-content-type-options',
    'via', 'cf-ray', 'x-cache', 'x-generator', 'x-drupal-cache',
    'x-wp-total', 'x-shopify-stage', 'x-amz-cf-id', 'x-vercel-id'
  ];
  const found = {};
  watch.forEach(h => { const v = res.headers.get(h); if (v) found[h] = v; });

  const tech = [];
  const hdr = (h) => (res.headers.get(h) || '').toLowerCase();
  if (res.headers.get('cf-ray'))                      tech.push('Cloudflare');
  if (res.headers.get('x-amz-cf-id'))                 tech.push('AWS CloudFront');
  if (res.headers.get('x-vercel-id'))                 tech.push('Vercel');
  if (hdr('x-powered-by').includes('express'))        tech.push('Express.js');
  if (hdr('x-powered-by').includes('php'))            tech.push('PHP');
  if (hdr('server').includes('nginx'))                tech.push('nginx');
  if (hdr('server').includes('apache'))               tech.push('Apache');
  if (hdr('server').includes('iis'))                  tech.push('IIS');
  if (res.headers.get('x-shopify-stage'))             tech.push('Shopify');
  if (res.headers.get('x-drupal-cache'))              tech.push('Drupal');
  if (res.headers.get('x-generator')?.toLowerCase().includes('wordpress')) tech.push('WordPress');

  const missing_sec = [];
  if (!res.headers.get('strict-transport-security'))  missing_sec.push('HSTS');
  if (!res.headers.get('x-frame-options'))            missing_sec.push('X-Frame-Options');
  if (!res.headers.get('content-security-policy'))    missing_sec.push('CSP');
  if (!res.headers.get('x-content-type-options'))     missing_sec.push('X-Content-Type-Options');

  return {
    status_code: res.status,
    headers: found,
    detected_tech: tech,
    missing_security_headers: missing_sec
  };
}

async function robots(domain) {
  const res = await safeFetch(`https://${domain}/robots.txt`);
  if (!res.ok) return { found: false, status: res.status };
  const text = await res.text();
  const extract = (pattern) =>
    (text.match(pattern) || []).map(l => l.replace(pattern.source.split(':')[0] + ': ', '').trim()).filter(Boolean);

  const disallowed = (text.match(/Disallow:\s*.+/gi) || []).map(l => l.replace(/Disallow:\s*/i, '').trim()).filter(Boolean);
  const allowed    = (text.match(/Allow:\s*.+/gi)    || []).map(l => l.replace(/Allow:\s*/i,    '').trim()).filter(Boolean);
  const sitemaps   = (text.match(/Sitemap:\s*.+/gi)  || []).map(l => l.replace(/Sitemap:\s*/i,  '').trim());
  const agents     = [...new Set((text.match(/User-agent:\s*.+/gi) || []).map(l => l.replace(/User-agent:\s*/i, '').trim()))];

  return {
    found: true,
    disallowed_count: disallowed.length,
    disallowed_paths: disallowed.slice(0, 30),
    allowed_paths: allowed.slice(0, 10),
    sitemaps,
    user_agents: agents
  };
}

async function emails(domain) {
  const res = await safeFetch(`https://crt.sh/?q=${domain}&output=json`, {}, 12000);
  const data = await res.json();
  const rx = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const found = new Set();
  data.forEach(cert => {
    (JSON.stringify(cert).match(rx) || [])
      .filter(e => e.toLowerCase().endsWith(domain))
      .forEach(e => found.add(e.toLowerCase()));
  });
  return { count: found.size, emails: [...found] };
}

async function sourcecode(domain) {
  const res = await safeFetch(`https://${domain}`);
  const html = await res.text();
  const emailRx = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const scripts  = [...html.matchAll(/<script[^>]*\ssrc=["']([^"']+)["']/gi)].map(m => m[1]);
  const comments = [...html.matchAll(/<!--([\s\S]*?)-->/g)]
    .map(m => m[1].trim()).filter(c => c.length > 5 && c.length < 400).slice(0, 8);
  const apiPaths = [...new Set(html.match(/["'](\/api\/[^"'\s<>]{1,100})["']/g) || [])]
    .map(e => e.replace(/["']/g, '')).slice(0, 20);
  const emailsFound = [...new Set(html.match(emailRx) || [])].slice(0, 10);

  return {
    page_size_kb: Math.round(html.length / 1024),
    scripts: {
      total: scripts.length,
      external: scripts.filter(s => s.startsWith('http')).slice(0, 10),
      internal: scripts.filter(s => !s.startsWith('http')).slice(0, 10)
    },
    html_comments: comments,
    api_paths_in_source: apiPaths,
    emails_in_source: emailsFound
  };
}

async function endpoints(domain) {
  const paths = [
    '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql', '/graphiql',
    '/swagger', '/swagger-ui.html', '/swagger-ui', '/api-docs',
    '/openapi.json', '/swagger.json', '/swagger.yaml', '/redoc',
    '/.well-known/openid-configuration', '/health', '/healthz',
    '/status', '/ping', '/metrics', '/api/health', '/api/status',
    '/v1', '/v2', '/v3', '/rest', '/rest/v1'
  ];
  const settled = await Promise.allSettled(
    paths.map(p =>
      safeFetch(`https://${domain}${p}`, { method: 'HEAD', redirect: 'follow' }, 5000)
        .then(r => ({ path: p, status: r.status }))
        .catch(() => null)
    )
  );
  const found = settled
    .filter(r => r.status === 'fulfilled' && r.value && r.value.status !== 404)
    .map(r => r.value)
    .sort((a, b) => a.status - b.status);
  return { checked: paths.length, found_count: found.length, endpoints: found };
}

async function adminpanels(domain) {
  const paths = [
    '/admin', '/administrator', '/admin/login', '/admin/index',
    '/wp-admin', '/wp-login.php', '/admin.php', '/login',
    '/dashboard', '/cpanel', '/webmail', '/phpmyadmin', '/pma',
    '/manager', '/backend', '/cms', '/console', '/control',
    '/admin/index.php', '/user/login', '/auth/login', '/auth',
    '/panel', '/adminpanel', '/moderator', '/webadmin', '/portal'
  ];
  const settled = await Promise.allSettled(
    paths.map(p =>
      safeFetch(`https://${domain}${p}`, { method: 'HEAD', redirect: 'follow' }, 5000)
        .then(r => ({ path: p, status: r.status }))
        .catch(() => null)
    )
  );
  const found = settled
    .filter(r => r.status === 'fulfilled' && r.value && [200, 301, 302, 403].includes(r.value.status))
    .map(r => r.value);
  return {
    checked: paths.length,
    found_count: found.length,
    panels: found,
    note: '403 = panel exists, access denied. Still a valid finding.'
  };
}

async function backlinks(domain) {
  const res = await safeFetch(
    `https://index.commoncrawl.org/CC-MAIN-2024-51-index?url=*.${domain}&output=json&limit=200&fl=url,timestamp`,
    {}, 12000
  );
  const text = await res.text();
  const entries = text.trim().split('\n').filter(Boolean)
    .map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const domains = [...new Set(entries.map(e => {
    try { return new URL(e.url).hostname.replace('www.', ''); } catch { return null; }
  }).filter(Boolean))];
  return {
    total_crawled: entries.length,
    unique_subdomains: domains.length,
    sample_subdomains: domains.slice(0, 25),
    oldest_crawl: entries[entries.length - 1]?.timestamp || null,
    newest_crawl: entries[0]?.timestamp || null
  };
}

async function indexing(domain) {
  const res = await safeFetch(
    `https://index.commoncrawl.org/CC-MAIN-2024-51-index?url=${domain}/*&output=json&limit=500&fl=url,status,timestamp`,
    {}, 12000
  );
  const text = await res.text();
  const pages = text.trim().split('\n').filter(Boolean)
    .map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  const statusBreakdown = {};
  pages.forEach(p => {
    const s = p.status || 'unknown';
    statusBreakdown[s] = (statusBreakdown[s] || 0) + 1;
  });
  return {
    indexed_pages: pages.length,
    sample_urls: pages.slice(0, 15).map(p => p.url),
    status_breakdown: statusBreakdown,
    source: 'CommonCrawl',
    note: pages.length === 0 ? 'Domain not yet in CommonCrawl index' : null
  };
}

// ─── Runner ───────────────────────────────────────────────────────────────────

const MODULE_MAP = {
  whois, subdomains, dns, ip, headers, robots,
  emails, sourcecode, endpoints, adminpanels, backlinks, indexing
};

async function runModules(domain, moduleList) {
  const settled = await Promise.allSettled(
    moduleList.map(async (name) => {
      const fn = MODULE_MAP[name];
      if (!fn) return { name, error: 'unknown module' };
      try {
        const data = await fn(domain);
        return { name, data };
      } catch (err) {
        return { name, error: err.message || 'module failed' };
      }
    })
  );
  const results = {};
  settled.forEach(r => {
    if (r.status === 'fulfilled') {
      const { name, data, error } = r.value;
      results[name] = error ? { error } : data;
    }
  });
  return results;
}

module.exports = { runModules, FREE_MODULES, PREMIUM_MODULES };


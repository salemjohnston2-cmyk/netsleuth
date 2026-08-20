import * as tls from 'tls';

export const NETSLEUTH_VERSION = '1.0.0';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ModuleStatus = 'completed' | 'failed' | 'skipped' | 'timeout';

export interface Finding {
  severity: Severity;
  title: string;
  description: string;
  evidence?: any;
  fix?: { title: string; description: string; code?: string; language?: string; };
}

export interface ModuleResult {
  module: string;
  status: ModuleStatus;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  data: any;
  findings: Finding[];
  error?: { code: string; message: string; };
}

export interface ScanResult {
  domain: string;
  started_at: string;
  completed_at: string;
  modules: Record<string, ModuleResult>;
  findings: Finding[];
}

// ─── UTILITIES ───────────────────────────────────────────────
async function safeFetch(url: string, options: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
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

// ─── MODULE 1: DNS ───────────────────────────────────────────
export async function scanDns(domain: string): Promise<ModuleResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  try {
    const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA'];
    const results: Record<string, string[]> = {};
    await Promise.all(types.map(async (type) => {
      try {
        const res = await safeFetch(`https://dns.google/resolve?name=${domain}&type=${type}`);
        const data = await res.json();
        if (data.Answer) results[type] = data.Answer.map((a: any) => a.data);
      } catch (e) {}
    }));
    return { module: 'dns', status: 'completed', started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), duration_ms: Date.now() - start, data: results, findings };
  } catch (err: any) {
    return { module: 'dns', status: 'failed', started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), duration_ms: Date.now() - start, data: null, findings, error: { code: 'NETWORK_ERROR', message: err.message } };
  }
}

// ─── MODULE 2: IP ────────────────────────────────────────────
export async function scanIp(domain: string): Promise<ModuleResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  try {
    const dnsRes = await safeFetch(`https://dns.google/resolve?name=${domain}&type=A`);
    const dnsData = await dnsRes.json();
    const ip = dnsData.Answer?.[0]?.data;
    if (!ip) throw new Error('Could not resolve IP');
    const geoRes = await safeFetch(`http://ip-api.com/json/${ip}?fields=country,regionName,city,isp,org,as,reverse,hosting,proxy`);
    const geo = await geoRes.json();
    return { module: 'ip', status: 'completed', started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), duration_ms: Date.now() - start, data: { ip, country: geo.country, region: geo.regionName, city: geo.city, isp: geo.isp, org: geo.org, asn: geo.as, is_hosting: geo.hosting }, findings };
  } catch (err: any) {
    return { module: 'ip', status: 'failed', started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), duration_ms: Date.now() - start, data: null, findings, error: { code: 'NETWORK_ERROR', message: err.message } };
  }
}

// ─── MODULE 3: HEADERS ───────────────────────────────────────
export async function scanHeaders(domain: string): Promise<ModuleResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  try {
    const res = await safeFetch(`https://${domain}`, { method: 'HEAD', redirect: 'follow' });
    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
    const securityHeaders = [
      { name: 'strict-transport-security', severity: 'high' as const, fix: 'Add HSTS header to force HTTPS.' },
      { name: 'content-security-policy', severity: 'medium' as const, fix: 'Add CSP to prevent XSS.' },
      { name: 'x-frame-options', severity: 'medium' as const, fix: 'Add X-Frame-Options to prevent clickjacking.' },
      { name: 'x-content-type-options', severity: 'low' as const, fix: 'Add nosniff to prevent MIME sniffing.' }
    ];
    securityHeaders.forEach(h => {
      if (!headers[h.name]) {
        findings.push({ severity: h.severity, title: `Missing ${h.name.toUpperCase()} header`, description: `The ${h.name} header is missing.`, fix: { title: 'Add Header', description: h.fix, code: `${h.name}: ...` } });
      }
    });
    return { module: 'headers', status: 'completed', started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), duration_ms: Date.now() - start, data: { status_code: res.status, headers }, findings };
  } catch (err: any) {
    return { module: 'headers', status: 'failed', started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), duration_ms: Date.now() - start, data: null, findings, error: { code: 'NETWORK_ERROR', message: err.message } };
  }
}

// ─── MODULE 4: SSL ───────────────────────────────────────────
export async function scanSsl(domain: string): Promise<ModuleResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  return new Promise((resolve) => {
    const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      if (!cert || !cert.subject) return resolve({ module: 'ssl', status: 'failed', started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), duration_ms: Date.now() - start, data: null, findings, error: { code: 'SSL_ERROR', message: 'No certificate returned' } });
      const validTo = new Date(cert.valid_to);
      const daysLeft = Math.ceil((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
      if (daysLeft < 30) findings.push({ severity: daysLeft < 7 ? 'critical' : 'high', title: 'SSL Certificate Expiring Soon', description: `Certificate expires in ${daysLeft} days.`, evidence: { valid_to: cert.valid_to } });
      resolve({ module: 'ssl', status: 'completed', started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), duration_ms: Date.now() - start, data: { subject: cert.subject.CN, issuer: cert.issuer.O || cert.issuer.CN, valid_to: cert.valid_to, days_until_expiry: daysLeft, protocol: socket.getProtocol(), cipher: socket.getCipher().name }, findings });
    });
    socket.on('error', (err) => resolve({ module: 'ssl', status: 'failed', started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), duration_ms: Date.now() - start, data: null, findings, error: { code: 'SSL_ERROR', message: err.message } }));
  });
}

// ─── MODULE 5: TECH STACK ────────────────────────────────────
export async function scanTechStack(domain: string): Promise<ModuleResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  try {
    const res = await safeFetch(`https://${domain}`, { method: 'HEAD', redirect: 'follow' });
    const tech: string[] = [];
    const server = res.headers.get('server') || '';
    const poweredBy = res.headers.get('x-powered-by') || '';
    if (res.headers.get('cf-ray')) tech.push('Cloudflare');
    if (server.toLowerCase().includes('nginx')) tech.push('nginx');
    if (server.toLowerCase().includes('apache')) tech.push('Apache');
    if (poweredBy.toLowerCase().includes('php')) tech.push('PHP');
    if (poweredBy.toLowerCase().includes('express')) tech.push('Express.js');
    if (res.headers.get('x-generator')?.toLowerCase().includes('wordpress')) tech.push('WordPress');
    return { module: 'techstack', status: 'completed', started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), duration_ms: Date.now() - start, data: { detected: tech }, findings };
  } catch (err: any) {
    return { module: 'techstack', status: 'failed', started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), duration_ms: Date.now() - start, data: null, findings, error: { code: 'NETWORK_ERROR', message: err.message } };
  }
}

// ─── RUNNER ──────────────────────────────────────────────────
export async function runScan(domain: string): Promise<ScanResult> {
  const start = Date.now();
  const modules: Record<string, ModuleResult> = {};
  const allFindings: Finding[] = [];
  const results = await Promise.allSettled([scanDns(domain), scanIp(domain), scanHeaders(domain), scanSsl(domain), scanTechStack(domain)]);
  results.forEach((result) => {
    if (result.status === 'fulfilled') {
      const moduleResult = result.value;
      modules[moduleResult.module] = moduleResult;
      allFindings.push(...moduleResult.findings);
    }
  });
  return { domain, started_at: new Date(start).toISOString(), completed_at: new Date().toISOString(), modules, findings: allFindings };
}

export function greet(): string { return 'NetSleuth Core Engine Initialized'; }

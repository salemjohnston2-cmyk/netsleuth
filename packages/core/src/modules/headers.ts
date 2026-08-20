import { safeFetch } from '../utils/fetch';
import { ModuleResult, Finding } from '../types';

export async function scanHeaders(domain: string): Promise<ModuleResult> {
  const start = Date.now();
  const findings: Finding[] = [];

  try {
    const res = await safeFetch(`https://${domain}`, { method: 'HEAD', redirect: 'follow' });
    const headers: Record<string, string> = {};
    
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    // Check Security Headers
    const securityHeaders = [
      { name: 'strict-transport-security', severity: 'high' as const, fix: 'Add HSTS header to force HTTPS.' },
      { name: 'content-security-policy', severity: 'medium' as const, fix: 'Add CSP to prevent XSS.' },
      { name: 'x-frame-options', severity: 'medium' as const, fix: 'Add X-Frame-Options to prevent clickjacking.' },
      { name: 'x-content-type-options', severity: 'low' as const, fix: 'Add nosniff to prevent MIME sniffing.' }
    ];

    securityHeaders.forEach(h => {
      if (!headers[h.name]) {
        findings.push({
          severity: h.severity,
          title: `Missing ${h.name.toUpperCase()} header`,
          description: `The ${h.name} header is missing.`,
          fix: { title: 'Add Header', description: h.fix, code: `${h.name}: ...` }
        });
      }
    });

    return {
      module: 'headers',
      status: 'completed',
      started_at: new Date(start).toISOString(),
      completed_at: new Date().toISOString(),
      duration_ms: Date.now() - start,
      data: { status_code: res.status, headers },
      findings
    };
  } catch (err: any) {
    return {
      module: 'headers',
      status: 'failed',
      started_at: new Date(start).toISOString(),
      completed_at: new Date().toISOString(),
      duration_ms: Date.now() - start,
      data: null,
      findings,
      error: { code: 'NETWORK_ERROR', message: err.message }
    };
  }
        } 

import { safeFetch } from '../utils/fetch';
import { ModuleResult, Finding } from '../types';

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

    return {
      module: 'techstack',
      status: 'completed',
      started_at: new Date(start).toISOString(),
      completed_at: new Date().toISOString(),
      duration_ms: Date.now() - start,
      data: { detected: tech },
      findings
    };
  } catch (err: any) {
    return {
      module: 'techstack',
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

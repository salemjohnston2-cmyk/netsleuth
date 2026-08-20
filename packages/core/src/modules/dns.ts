import { safeFetch } from '../utils/fetch';
import { ModuleResult, Finding } from '../types';

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
        if (data.Answer) {
          results[type] = data.Answer.map((a: any) => a.data);
        }
      } catch (e) { /* Ignore individual record failures */ }
    }));

    // Check for missing MX (Email security)
    if (!results['MX'] || results['MX'].length === 0) {
      findings.push({
        severity: 'info',
        title: 'No MX Records Found',
        description: 'This domain does not appear to be configured to receive email.'
      });
    }

    return {
      module: 'dns',
      status: 'completed',
      started_at: new Date(start).toISOString(),
      completed_at: new Date().toISOString(),
      duration_ms: Date.now() - start,
      data: results,
      findings
    };
  } catch (err: any) {
    return {
      module: 'dns',
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

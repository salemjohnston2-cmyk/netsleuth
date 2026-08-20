import { ScanResult, ModuleResult, Finding } from './types';
import { scanDns } from './modules/dns';
import { scanIp } from './modules/ip';
import { scanHeaders } from './modules/headers';
import { scanSsl } from './modules/ssl';
import { scanTechStack } from './modules/techstack';

export async function runScan(domain: string): Promise<ScanResult> {
  const start = Date.now();
  const modules: Record<string, ModuleResult> = {};
  const allFindings: Finding[] = [];

  // Run modules in parallel where possible
  const results = await Promise.allSettled([
    scanDns(domain),
    scanIp(domain),
    scanHeaders(domain),
    scanSsl(domain),
    scanTechStack(domain)
  ]);

  results.forEach((result) => {
    if (result.status === 'fulfilled') {
      const moduleResult = result.value;
      modules[moduleResult.module] = moduleResult;
      allFindings.push(...moduleResult.findings);
    }
  });

  return {
    domain,
    started_at: new Date(start).toISOString(),
    completed_at: new Date().toISOString(),
    modules,
    findings: allFindings
  };
} 

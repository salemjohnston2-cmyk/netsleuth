import { safeFetch } from '../utils/fetch';
import { ModuleResult, Finding } from '../types';

export async function scanIp(domain: string): Promise<ModuleResult> {
  const start = Date.now();
  const findings: Finding[] = [];

  try {
    // Resolve IP first
    const dnsRes = await safeFetch(`https://dns.google/resolve?name=${domain}&type=A`);
    const dnsData = await dnsRes.json();
    const ip = dnsData.Answer?.[0]?.data;

    if (!ip) throw new Error('Could not resolve IP');

    // Get Geo/ASN data
    const geoRes = await safeFetch(`http://ip-api.com/json/${ip}?fields=country,regionName,city,isp,org,as,reverse,hosting,proxy`);
    const geo = await geoRes.json();

    if (geo.proxy) {
      findings.push({
        severity: 'medium',
        title: 'IP is a Proxy/VPN',
        description: `The IP address ${ip} appears to be a proxy or VPN.`,
        evidence: { isp: geo.isp }
      });
    }

    return {
      module: 'ip',
      status: 'completed',
      started_at: new Date(start).toISOString(),
      completed_at: new Date().toISOString(),
      duration_ms: Date.now() - start,
      data: {
        ip,
        country: geo.country,
        region: geo.regionName,
        city: geo.city,
        isp: geo.isp,
        org: geo.org,
        asn: geo.as,
        is_hosting: geo.hosting
      },
      findings
    };
  } catch (err: any) {
    return {
      module: 'ip',
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

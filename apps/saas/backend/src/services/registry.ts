import { 
  scanDns, scanIp, scanHeaders, scanSsl, scanTechStack,
  scanWhois, scanSubdomains, scanPortscan, scanCors, scanExposure, scanWaf,
  ModuleResult 
} from '@netsleuth/core';

export const MODULE_REGISTRY: Record<string, (domain: string) => Promise<ModuleResult>> = {
  dns: scanDns,
  ip: scanIp,
  headers: scanHeaders,
  ssl: scanSsl,
  techstack: scanTechStack,
  whois: scanWhois,
  subdomains: scanSubdomains,
  portscan: scanPortscan,
  cors: scanCors,
  exposure: scanExposure,
  waf: scanWaf
};

export const AVAILABLE_MODULES = Object.keys(MODULE_REGISTRY);

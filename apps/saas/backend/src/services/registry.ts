import { 
  scanDns, 
  scanIp, 
  scanHeaders, 
  scanSsl, 
  scanTechStack,
  ModuleResult 
} from '@netsleuth/core';

// Maps database module names to core engine functions
export const MODULE_REGISTRY: Record<string, (domain: string) => Promise<ModuleResult>> = {
  dns: scanDns,
  ip: scanIp,
  headers: scanHeaders,
  ssl: scanSsl,
  techstack: scanTechStack,
  
  // Future modules will be added here in Phase 5 & 6
  // For now, we only process the 5 we have built
};

export const AVAILABLE_MODULES = Object.keys(MODULE_REGISTRY);

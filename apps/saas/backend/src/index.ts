export const NETSLEUTH_VERSION = '1.0.0';
export * from './types';
export { runScan } from './runner';

// Export individual modules for the backend registry
export { scanDns } from './modules/dns';
export { scanIp } from './modules/ip';
export { scanHeaders } from './modules/headers';
export { scanSsl } from './modules/ssl';
export { scanTechStack } from './modules/techstack';

export function greet(): string {
  return 'NetSleuth Core Engine Initialized';
}

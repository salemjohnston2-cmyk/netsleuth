export const NETSLEUTH_VERSION = '1.0.0';
export * from './types';
export { runScan } from './runner';

export function greet(): string {
  return 'NetSleuth Core Engine Initialized';
}

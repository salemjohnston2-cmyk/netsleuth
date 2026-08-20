import * as tls from 'tls';
import { ModuleResult, Finding } from '../types';

export async function scanSsl(domain: string): Promise<ModuleResult> {
  const start = Date.now();
  const findings: Finding[] = [];

  return new Promise((resolve) => {
    const socket = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();

      if (!cert || !cert.subject) {
        return resolve({
          module: 'ssl',
          status: 'failed',
          started_at: new Date(start).toISOString(),
          completed_at: new Date().toISOString(),
          duration_ms: Date.now() - start,
          data: null,
          findings,
          error: { code: 'SSL_ERROR', message: 'No certificate returned' }
        });
      }

      const validTo = new Date(cert.valid_to);
      const daysLeft = Math.ceil((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));

      if (daysLeft < 30) {
        findings.push({
          severity: daysLeft < 7 ? 'critical' : 'high',
          title: 'SSL Certificate Expiring Soon',
          description: `Certificate expires in ${daysLeft} days.`,
          evidence: { valid_to: cert.valid_to }
        });
      }

      resolve({
        module: 'ssl',
        status: 'completed',
        started_at: new Date(start).toISOString(),
        completed_at: new Date().toISOString(),
        duration_ms: Date.now() - start,
        data: {
          subject: cert.subject.CN,
          issuer: cert.issuer.O || cert.issuer.CN,
          valid_to: cert.valid_to,
          days_until_expiry: daysLeft,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher().name
        },
        findings
      });
    });

    socket.on('error', (err) => {
      resolve({
        module: 'ssl',
        status: 'failed',
        started_at: new Date(start).toISOString(),
        completed_at: new Date().toISOString(),
        duration_ms: Date.now() - start,
        data: null,
        findings,
        error: { code: 'SSL_ERROR', message: err.message }
      });
    });
  });
              } 

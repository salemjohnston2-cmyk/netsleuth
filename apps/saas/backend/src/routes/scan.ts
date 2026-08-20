import { Router } from 'express';
import { supabaseAdmin } from '../lib/supabase';
import { startScan } from '../services/scanner';

const router = Router();

// Start a scan
router.post('/start', async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain required' });

    // For now, userId is null (public scan). Auth will be added in Phase 6.
    const scanId = await startScan(domain, null);
    res.json({ scan_id: scanId });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// SSE Stream
router.get('/stream/:id', async (req, res) => {
  const scanId = req.params.id;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // Nginx/Cloudflare fix

  const interval = setInterval(async () => {
    try {
      const { data: scan } = await supabaseAdmin
        .from('scans')
        .select('*, module_results(*, sites(domain))')
        .eq('id', scanId)
        .single();

      if (!scan) return;

      // Push update
      res.write(`data: ${JSON.stringify({
        scan_id: scan.id,
        status: scan.status,
        progress: scan.progress_percent,
        modules: scan.module_results
      })}\n\n`);

      // Close connection if done
      if (scan.status === 'completed' || scan.status === 'failed') {
        clearInterval(interval);
        res.end();
      }
    } catch (err) {
      clearInterval(interval);
      res.end();
    }
  }, 1000);

  req.on('close', () => clearInterval(interval));
});

export default router; 

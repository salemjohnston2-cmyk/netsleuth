import { Router } from 'express';
import { supabaseAdmin } from '../lib/supabase';
import { startScan } from '../services/scanner';

const router = Router();

// HACK: Accept BOTH GET and POST so we can test from a mobile browser address bar
router.all('/start', async (req, res) => {
  try {
    // Grab domain from URL (?domain=github.com) OR from JSON body
    const domain = (req.query.domain as string) || req.body?.domain;
    
    if (!domain) {
      return res.status(400).json({ 
        error: 'Domain required. Add ?domain=example.com to the URL.' 
      });
    }

    const scanId = await startScan(domain, null);
    
    res.json({ 
      message: 'Scan started!',
      scan_id: scanId,
      // This gives you the exact link to copy/paste for the next step
      stream_link: `/scan/stream/${scanId}` 
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// SSE Stream (Remains exactly the same)
router.get('/stream/:id', async (req, res) => {
  const scanId = req.params.id;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const interval = setInterval(async () => {
    try {
      const { data: scan } = await supabaseAdmin
        .from('scans')
        .select('*, module_results(*)')
        .eq('id', scanId)
        .single();

      if (!scan) return;

      res.write(`data: ${JSON.stringify({
        scan_id: scan.id,
        status: scan.status,
        progress: scan.progress_percent,
        modules: scan.module_results
      })}\n\n`);

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

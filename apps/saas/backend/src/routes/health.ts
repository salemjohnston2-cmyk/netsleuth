import { Router } from 'express';
import { supabaseAdmin } from '../lib/supabase';

const router = Router();

router.get('/', async (req, res) => {
  try {
    const { error } = await supabaseAdmin
      .from('profiles')
      .select('*', { count: 'exact', head: true });

    if (error) throw error;

    res.json({
      status: 'ok',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (err: any) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

export default router;

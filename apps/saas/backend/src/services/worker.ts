import { supabaseAdmin } from '../lib/supabase';
import { MODULE_REGISTRY } from './registry';

let isProcessing = false;

async function processQueue() {
  if (isProcessing) return;
  isProcessing = true;

  try {
    // 1. Grab next pending job
    const { data: job } = await supabaseAdmin
      .from('scan_queue')
      .select('*')
      .eq('status', 'pending')
      .order('created_at', { ascending: true })
      .limit(1)
      .maybeSingle();

    if (!job) {
      isProcessing = false;
      return; // Queue empty
    }

    // 2. Lock the job
    await supabaseAdmin
      .from('scan_queue')
      .update({ status: 'processing', locked_at: new Date().toISOString() })
      .eq('id', job.id);

    // 3. Execute Module
    const moduleFn = MODULE_REGISTRY[job.module_name];
    if (!moduleFn) {
      await finishJob(job.id, job.scan_id, 'failed', null, 'Module not implemented yet');
      isProcessing = false;
      return;
    }

    // Get domain from scan record (safely)
    const { data: scan } = await supabaseAdmin
      .from('scans')
      .select('site_id')
      .eq('id', job.scan_id)
      .single();

    if (!scan) throw new Error('Scan record not found');

    const { data: site } = await supabaseAdmin
      .from('sites')
      .select('domain')
      .eq('id', scan.site_id)
      .single();

    if (!site) throw new Error('Site record not found');
    
    const domain = site.domain;

    console.log(`⚙️ Processing ${job.module_name} for ${domain}`);
    const result = await moduleFn(domain);

    // 4. Save Result & Finish Job (Pass null if error message is undefined)
    await finishJob(job.id, job.scan_id, result.status, result, result.error?.message ?? null);

  } catch (err: any) {
    console.error('Worker error:', err);
  } finally {
    isProcessing = false;
  }
}

async function finishJob(jobId: string, scanId: string, status: string, result: any, error: string | null) {
  // Update Job Status
  await supabaseAdmin
    .from('scan_queue')
    .update({ status: 'completed', completed_at: new Date().toISOString() })
    .eq('id', jobId);

  // Save Module Result
  if (result) {
    await supabaseAdmin
      .from('module_results')
      .insert({
        scan_id: scanId,
        module_name: result.module,
        status: result.status,
        data: result.data,
        error_message: error,
        duration_ms: result.duration_ms
      });
  }

  // Update Master Scan Progress
  const { count: completed } = await supabaseAdmin
    .from('scan_queue')
    .select('*', { count: 'exact', head: true })
    .eq('scan_id', scanId)
    .eq('status', 'completed');

  const { count: total } = await supabaseAdmin
    .from('scan_queue')
    .select('*', { count: 'exact', head: true })
    .eq('scan_id', scanId);

  const progress = Math.round(((completed || 0) / (total || 1)) * 100);

  await supabaseAdmin
    .from('scans')
    .update({ 
      status: progress === 100 ? 'completed' : 'running',
      completed_modules: completed,
      progress_percent: progress,
      completed_at: progress === 100 ? new Date().toISOString() : null
    })
    .eq('id', scanId);
}

export function startWorker() {
  console.log('🤖 Worker started. Polling queue every 2s...');
  // Poll every 2 seconds
  setInterval(processQueue, 2000);
        }

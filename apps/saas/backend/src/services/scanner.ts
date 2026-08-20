import { supabaseAdmin } from '../lib/supabase';
import { AVAILABLE_MODULES } from './registry';

export async function startScan(domain: string, userId: string | null) {
  // 1. Normalize domain
  const normalized = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

  // 2. Find or Create Site
  let { data: site } = await supabaseAdmin
    .from('sites')
    .select('id')
    .eq('normalized_domain', normalized)
    .maybeSingle();

  if (!site) {
    const { data: newSite } = await supabaseAdmin
      .from('sites')
      .insert({ domain: normalized, normalized_domain: normalized, user_id: userId })
      .select()
      .single();
    site = newSite;
  }

  // 3. Create Master Scan Record
  const { data: scan } = await supabaseAdmin
    .from('scans')
    .insert({ 
      site_id: site.id, 
      user_id: userId,
      status: 'pending',
      total_modules: AVAILABLE_MODULES.length 
    })
    .select()
    .single();

  // 4. Queue Modules
  const jobs = AVAILABLE_MODULES.map(module_name => ({
    scan_id: scan.id,
    module_name,
    status: 'pending'
  }));

  await supabaseAdmin.from('scan_queue').insert(jobs);

  return scan.id;
      } 

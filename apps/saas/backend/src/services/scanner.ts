import { supabaseAdmin } from '../lib/supabase';
import { AVAILABLE_MODULES } from './registry';

export async function startScan(domain: string, userId: string | null) {
  // 1. Normalize domain
  const normalized = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

  // 2. Find existing site
  let { data: existingSite } = await supabaseAdmin
    .from('sites')
    .select('id')
    .eq('normalized_domain', normalized)
    .maybeSingle();

  let siteId: string;

  if (existingSite) {
    siteId = existingSite.id;
  } else {
    // Create new site
    const { data: newSite, error } = await supabaseAdmin
      .from('sites')
      .insert({ domain: normalized, normalized_domain: normalized, user_id: userId })
      .select('id')
      .single();
      
    if (error || !newSite) throw new Error('Failed to create site: ' + error?.message);
    siteId = newSite.id;
  }

  // 3. Create Master Scan Record
  const { data: scan, error: scanError } = await supabaseAdmin
    .from('scans')
    .insert({ 
      site_id: siteId, 
      user_id: userId,
      status: 'pending',
      total_modules: AVAILABLE_MODULES.length 
    })
    .select('id')
    .single();

  if (scanError || !scan) throw new Error('Failed to create scan: ' + scanError?.message);

  // 4. Queue Modules
  const jobs = AVAILABLE_MODULES.map(module_name => ({
    scan_id: scan.id,
    module_name,
    status: 'pending'
  }));

  await supabaseAdmin.from('scan_queue').insert(jobs);

  return scan.id;
}

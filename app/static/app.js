'use strict';
const $ = (s, root = document) => root.querySelector(s);
const escapeHTML = value => { const n = document.createElement('span'); n.textContent = String(value ?? ''); return n.innerHTML; };
const e = escapeHTML;
const iconPaths = {
 overview:'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
 inventory:'M3 6l9-4 9 4-9 4-9-4zm0 6 9 4 9-4M3 18l9 4 9-4',
 findings:'M12 3 2 21h20L12 3zm0 6v5m0 3v1',
 graph:'M6 6h1m10 0h1M6 18h1m10 0h1M7 6l10 12M7 18 17 6M3 3h6v6H3zM15 3h6v6h-6zM3 15h6v6H3zM15 15h6v6h-6z',
 connections:'M8 3v4m8-4v4M6 7h12v5a6 6 0 0 1-12 0V7zm6 11v4',
 jobs:'M12 8v5l4 2M21 12a9 9 0 1 1-3-6M21 3v5h-5',
 access:'M14 10a5 5 0 1 0-2 4l4 4h3v3h3v-4l-8-7z',
 audit:'M5 3h14v18H5zM8 7h8M8 11h8M8 15h5'
};
const icon = name => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${iconPaths[name] || iconPaths.inventory}"/></svg>`;
const pages = {overview:['Overview','Your cloud posture, with the evidence behind it.'], inventory:['Cloud inventory','Query the configuration metadata collected from your accounts.'], findings:['Risk queue','Prioritize observed risks. Review evidence before making a change.'], graph:['Exposure model','Explore resource relationships and candidate public exposure.'], connections:['Connections','Choose what to collect, where to collect it, and how often.'], jobs:['Scan history','Every scan has a budget and an explicit coverage report.'], access:['Access & API keys','Workspace roles and revocable, scoped API access.'], audit:['Activity','Who changed what, and when.']};
let workspace = null, allWorkspaces = [], page = 'overview', summary = null, connections = [], refreshTimer = null, searchTimer;
let resourceOffset = 0, findingOffset = 0, resourceFilters = {}, findingStatus = 'open';
const admin = () => ['owner','admin'].includes(workspace?.role);
const analyst = () => ['owner','admin','analyst'].includes(workspace?.role);
const pill = value => `<span class="pill ${e(value)}">${e(value)}</span>`;
const date = value => value ? new Date(value.endsWith('Z') ? value : value + 'Z').toLocaleString() : '—';
const rel = value => value ? date(value) : 'No scans yet';
function toast(message) { const n = $('#toast'); n.textContent = message; n.hidden = false; clearTimeout(n.timeout); n.timeout = setTimeout(() => n.hidden = true, 6000); }
async function api(path, options = {}) {
 const headers = options.body && !(options.body instanceof FormData) ? {'Content-Type':'application/json'} : {};
 const response = await fetch(path, {...options, headers: {...headers, ...(options.headers || {})}, credentials:'same-origin'});
 const data = await response.json().catch(() => ({}));
 if (!response.ok) { if (response.status === 401) showLogin(); throw new Error(typeof data.detail === 'string' ? data.detail : 'The request could not be validated. Check the form fields.'); }
 return data;
}
const route = suffix => `/api/workspaces/${workspace.id}/${suffix}`;
const post = (path, value = {}) => api(path,{method:'POST',body:JSON.stringify(value)});
function showLogin() { $('#login-screen').hidden = false; $('#application').hidden = true; clearInterval(refreshTimer); }
function modal(html) { $('#dialog-body').innerHTML = html; $('#dialog').showModal(); }
function empty(title, text, action = '') { return `<div class="card empty"><div class="service-icon">◇</div><h2>${e(title)}</h2><p>${e(text)}</p>${action}</div>`; }
function button(text, action, cls = '', id = '') { return `<button class="${e(cls)}" data-action="${e(action)}" data-id="${e(id)}">${e(text)}</button>`; }
function heading() {
 const info = pages[page]; $('#breadcrumb').textContent = info[0];
 $('#page-heading').innerHTML = `<div><h1>${e(info[0])}</h1><p>${e(info[1])}</p></div>${page === 'connections' && admin() ? button('+ Add connection','add-connection','primary') : button('↻ Refresh','refresh')}`;
 for (const n of $('#navigation').children) n.classList.toggle('active', n.dataset.page === page);
}
async function loadWorkspaces() {
 allWorkspaces = await api('/api/workspaces');
 workspace = allWorkspaces.find(w => w.id === workspace?.id) || allWorkspaces[0];
 $('#workspace-picker').innerHTML = allWorkspaces.map(w => `<option value="${w.id}">${e(w.name)}</option>`).join('');
 if (workspace) { $('#workspace-picker').value = workspace.id; $('#role').textContent = workspace.role; }
}
async function start() {
 try {
  const me = await api('/api/me'); $('#identity').textContent = me.email; $('#avatar').textContent = me.email.slice(0,2).toUpperCase();
  await loadWorkspaces(); $('#login-screen').hidden = true; $('#application').hidden = false;
  $('#navigation').innerHTML = Object.entries(pages).map(([key,info]) => `<button data-page="${key}">${icon(key)}${e(info[0])}</button>`).join('');
  await render();
  clearInterval(refreshTimer); refreshTimer = setInterval(async () => { if (page === 'jobs' || page === 'overview') await render(false); },15000);
 } catch(error) { if (!$('#application').hidden) toast(error.message); }
}
async function render(loading = true) {
 heading(); if (!workspace) { $('#page-content').innerHTML = empty('Start with a workspace','Keep cloud accounts, findings, and people together.',button('Create workspace','new-workspace','primary')); return; }
 if (loading) $('#page-content').innerHTML = '<div class="loading">Loading your workspace…</div>';
 try {
  [summary,connections] = await Promise.all([api(route('summary')),api(route('connections'))]);
  $('#demo-notice').hidden = !summary.synthetic;
  await ({overview:overview, inventory:inventory, findings:findings, graph:exposure, connections:connectionPage, jobs:jobs, access:accessPage, audit:activity})[page]();
 } catch (error) { $('#page-content').innerHTML = empty('Could not load this view',error.message,button('Try again','refresh')); }
}
async function overview() {
 const risks = (await api(route('findings?status=open&limit=5'))).items;
 const latest = summary.latest_scans, unknown = latest.reduce((n,j) => n + j.coverage.filter(c => c.status !== 'complete').length + (j.assessment.unknown || 0), 0);
 const metrics = [['Observed resources',summary.resource_count,'Current snapshot metadata','inventory'],['Open findings',summary.open_findings,'Accepted risks excluded','findings'],['Connected sources',summary.connection_count,'AWS, GitHub, and reports','connections'],['Coverage gaps',unknown,'Incomplete scopes + unknown checks','jobs']];
 let html = `<div class="metrics">${metrics.map(([label,value,small,ic]) => `<div class="metric"><div class="metric-top">${e(label)}${icon(ic)}</div><strong>${value}</strong><small>${e(small)}</small></div>`).join('')}</div>`;
 if (!connections.length) html += `<div class="welcome-strip"><div><strong>Start small. Build a clear picture.</strong><p>Connect one AWS region, or try synthetic data to explore the workflow.</p></div><div class="buttons">${admin() ? button('Connect AWS','add-connection','primary')+button('Try demo data','demo') : ''}</div></div>`;
 html += `<div class="two-columns"><div class="card"><div class="card-head"><h2>Your next priorities</h2><a href="#findings" data-page="findings">View risk queue →</a></div>${risks.length ? risks.map(f => `<div class="row-item"><span class="score">${f.score}</span><div class="grow"><strong>${e(f.title)}</strong><small>${e(f.check_id)} · ${e(f.resource_uid)}</small></div>${pill(f.severity)}${button('↗','finding','',f.id)}</div>`).join('') : '<div class="empty"><p>No open findings are recorded. Review scan coverage before interpreting this result.</p></div>'}</div><div class="card"><div class="card-head"><h2>Risk distribution</h2><span class="muted fine">Open findings</span></div><div class="card-body">${['critical','high','medium','low','info'].map(s => `<div class="bar-row"><span>${s[0].toUpperCase()+s.slice(1)}</span><div class="bar-track"><div class="bar-fill ${s}" data-width="${summary.open_findings ? 100*(summary.severities[s] || 0)/summary.open_findings : 0}"></div></div><strong>${summary.severities[s] || 0}</strong></div>`).join('')}</div></div></div>`;
 html += `<div class="two-columns"><div class="card"><div class="card-head"><h2>Cloud footprint</h2><a href="#inventory" data-page="inventory">Explore inventory →</a></div>${Object.entries(summary.resource_kinds).map(([kind,count]) => `<div class="row-item"><span class="service-icon">${e(kind.split('.')[0].toUpperCase())}</span><div class="grow"><strong>${e(kind)}</strong><small>Configuration metadata</small></div><strong>${count}</strong></div>`).join('') || '<div class="empty"><p>Your collected resource types will appear here.</p></div>'}</div><div class="card"><div class="card-head"><h2>A deliberate data budget</h2></div><div class="card-body"><div class="limit-grid"><div><strong>1,000</strong><span>default resources / scan</span></div><div><strong>300</strong><span>default logical API calls</span></div><div><strong>0</strong><span>snapshots or image pulls</span></div></div><p class="fine">Only selected regions and supported services are collected. API denials and limits stay visible.</p><a class="fine" href="https://github.com/quentinmayo/MayoCSPM/blob/main/docs/DATA-BUDGET.md">Read the collection contract ↗</a></div></div></div>`;
 $('#page-content').innerHTML = html;
 for (const bar of document.querySelectorAll('[data-width]')) bar.style.width = `${bar.dataset.width}%`;
}
async function inventory() {
 const filters = new URLSearchParams({...resourceFilters,offset:resourceOffset,limit:100});
 const data = await api(route('resources?'+filters));
 $('#page-content').innerHTML = `<div class="toolbar"><input id="resource-search" aria-label="Search inventory" placeholder="Search resource name or ID…" value="${e(resourceFilters.q || '')}"><select id="kind-filter" aria-label="Resource type"><option value="">All resource types</option>${Object.keys(summary.resource_kinds).map(k => `<option ${resourceFilters.kind === k ? 'selected' : ''}>${e(k)}</option>`).join('')}</select><input id="region-filter" aria-label="Region" placeholder="Region (optional)" value="${e(resourceFilters.region || '')}"><input id="tag-filter" aria-label="Tag filter" placeholder="Tag key=value (optional)" value="${e(resourceFilters.tag_key ? resourceFilters.tag_key+'='+resourceFilters.tag_value : '')}">${button('Apply filters','filter-resources')}</div><div class="card"><div class="card-head"><h2>${data.total} resources</h2><span class="fine muted">Current snapshot · Metadata only</span></div><div class="table-scroll"><table><thead><tr><th>Resource</th><th>Type</th><th>Region</th><th>Last observed</th><th></th></tr></thead><tbody>${data.items.map(r => `<tr><td><strong>${e(r.name)}</strong><small>${e(r.uid)}</small></td><td>${e(r.kind)}</td><td>${e(r.region)}</td><td>${e(date(r.seen))}</td><td>${button('Inspect','resource','',r.id)}</td></tr>`).join('') || '<tr><td colspan="5">No resources match these filters.</td></tr>'}</tbody></table></div>${pagination(resourceOffset,data.total,'resource')}</div><p class="fine">Queries filter this workspace’s stored metadata. They never issue live AWS calls or execute arbitrary SQL.</p>`;
}
function pagination(offset,total,type) { return `<div class="pagination"><span>${Math.min(offset+1,total)}–${Math.min(offset+100,total)} of ${total}</span><button data-action="${type}-prev" ${!offset ? 'disabled' : ''}>Previous</button><button data-action="${type}-next" ${offset+100 >= total ? 'disabled' : ''}>Next</button></div>`; }
async function findings() {
 const data = await api(route(`findings?status=${findingStatus}&limit=100&offset=${findingOffset}`));
 $('#page-content').innerHTML = `<div class="toolbar"><select id="finding-status" aria-label="Finding status">${['open','accepted','resolved'].map(s => `<option ${s === findingStatus ? 'selected' : ''}>${s}</option>`).join('')}</select><span class="fine muted">${data.total} findings · Ranked by explainable risk score</span></div><div class="card"><div class="table-scroll"><table><thead><tr><th>Risk</th><th>Finding</th><th>Severity</th><th>Status</th><th>Last observed</th><th></th></tr></thead><tbody>${data.items.map(f => `<tr><td><span class="score">${f.score}</span></td><td><strong>${e(f.title)}</strong><small>${e(f.check_id)} · ${e(f.resource_uid)}</small></td><td>${pill(f.severity)}</td><td>${pill(f.status)}</td><td>${e(date(f.last_seen))}</td><td>${button('Evidence','finding','',f.id)}</td></tr>`).join('') || '<tr><td colspan="6">No findings in this status. Scan coverage remains a separate measure.</td></tr>'}</tbody></table></div>${pagination(findingOffset,data.total,'finding')}</div>`;
}
async function exposure() {
 const g = await api(route('graph'));
 const meaningful = g.nodes.filter(n => n.id !== 'internet');
 let html = `<div class="notice">Potential exposure is based on configuration. Routing, network ACLs, listening services, and end-to-end reachability are not verified.</div>`;
 if (!meaningful.length) { $('#page-content').innerHTML = html + empty('No relationships to model yet','Run a scan to see collected resources and their connections.'); return; }
 const shown = [g.nodes[0], ...meaningful.slice(0,35)], positions = new Map();
 const height = Math.max(480,Math.ceil((shown.length-1)/3)*115+60);
 positions.set('internet',{x:110,y:height/2});
 shown.slice(1).forEach((n,i) => positions.set(n.id,{x:350+(i%3)*215,y:70+Math.floor(i/3)*115}));
 const lines = g.edges.filter(edge => positions.has(edge.source) && positions.has(edge.target)).map(edge => { const a=positions.get(edge.source),b=positions.get(edge.target); return `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" class="${edge.confidence === 'candidate' ? 'candidate' : ''}"><title>${e(edge.relation)} · ${e(edge.confidence)}</title></line>`; }).join('');
 const nodes = shown.map(n => { const p = positions.get(n.id); return `<g class="${e(n.exposure)}"><rect x="${p.x-80}" y="${p.y-27}" width="160" height="54" rx="10"/><text x="${p.x}" y="${p.y-3}" text-anchor="middle">${e(n.label.length>23 ? n.label.slice(0,22)+'…' : n.label)}</text><text class="node-kind" x="${p.x}" y="${p.y+13}" text-anchor="middle">${e(n.kind)} · ${e(n.exposure.replace('_',' '))}</text><title>${e(n.label)} — ${e(n.region || '')}</title></g>`; }).join('');
 html += `<div class="card"><div class="card-head"><h2>Configuration relationships</h2><span class="fine muted">${g.nodes.length-1} resources · ${g.edges.length} relationships</span></div><div class="graph-wrap"><svg role="img" aria-label="Cloud resource exposure relationship diagram" viewBox="0 0 900 ${height}" data-height="${height}">${lines}${nodes}</svg></div><div class="graph-legend"><span>— Observed attachment / declared repository</span><span>┄ Candidate public configuration</span><span>Not observed ≠ proven private</span></div><p class="graph-description">${e(g.model)} ${meaningful.length > 35 ? 'Diagram shows the first 35 resources; the API returns up to 1,000.' : ''} ${g.truncated ? 'The 1,000-resource graph budget was reached.' : ''}</p></div><div class="card"><div class="card-head"><h2>Relationship evidence</h2></div><div class="table-scroll"><table><thead><tr><th>Relationship</th><th>Confidence</th><th>Target</th></tr></thead><tbody>${g.edges.slice(0,100).map(edge => `<tr><td>${e(edge.relation)}</td><td>${pill(edge.confidence)}</td><td>${e(g.nodes.find(n => n.id === edge.target)?.label || edge.target)}</td></tr>`).join('')}</tbody></table></div></div>`;
 $('#page-content').innerHTML = html; $('.graph-wrap svg').style.height = `${height}px`;
}
async function connectionPage() {
 if (!connections.length) { $('#page-content').innerHTML = empty('Your cloud starts here','Add an AWS role for read-only metadata collection, import a repository report, or explore synthetic demo data.',admin() ? button('Add connection','add-connection','primary')+' '+button('Try demo data','demo') : 'Ask a workspace administrator to add a connection.'); return; }
 $('#page-content').innerHTML = `<div class="connection-grid">${connections.map(c => `<div class="card"><div class="card-body"><div class="connection-header"><span class="service-icon">${e(c.kind.toUpperCase())}</span><div class="grow"><strong>${e(c.name)}</strong><small>${c.kind === 'demo' ? 'Synthetic configuration data' : c.kind === 'aws' ? 'Read-only AWS role' : 'Optional application security source'}</small></div></div><div class="connection-details"><div><span>Connection status</span>${pill(c.validated ? 'completed' : 'unknown')}</div><div><span>Schedule</span><strong>${c.interval_hours ? `Every ${c.interval_hours}h (UTC)` : 'Manual only'}</strong></div>${c.kind === 'aws' ? `<div><span>Regions</span><strong>${e(c.config.regions.join(', '))}</strong></div><div><span>Resource / call budget</span><strong>${c.config.max_resources} / ${c.config.max_api_calls}</strong></div><span class="arn">${e(c.config.role_arn)}</span>${admin() ? `<span>External ID</span><code>${e(c.external_id)}</code>` : ''}` : c.config.repository ? `<span class="arn">${e(c.config.repository)}</span>` : ''}</div><div class="connection-actions">${analyst() && c.kind !== 'sarif' ? button(c.validated ? 'Run scan' : 'Validate & scan','scan','primary',c.id) : ''}${admin() && c.kind !== 'sarif' ? button('Schedule','schedule','',c.id) : ''}${analyst() && c.kind === 'sarif' ? button('Upload SARIF','upload','primary',c.id) : ''}</div></div></div>`).join('')}</div><p class="fine">AWS validation rejects roles that can be assumed without the correct external ID. Missing permissions are reported as unknown coverage.</p>`;
}
async function jobs() {
 const rows = await api(route('jobs'));
 $('#page-content').innerHTML = `<div class="card"><div class="card-head"><h2>Recent scans</h2><span class="fine muted">Worker polls every 3 seconds</span></div><div class="table-scroll"><table><thead><tr><th>Run</th><th>Connection</th><th>Status</th><th>Resources</th><th>Checks</th><th>Started</th><th></th></tr></thead><tbody>${rows.map(j => `<tr><td><strong>#${j.id}</strong><small>${e(j.action)}</small></td><td>${e(connections.find(c => c.id === j.connection_id)?.name || j.connection_id)}</td><td>${pill(j.status)}</td><td>${j.resource_count}</td><td><small>${j.assessment.pass || 0} pass · ${j.assessment.fail || 0} fail · ${j.assessment.unknown || 0} unknown</small></td><td>${e(date(j.created))}</td><td>${button('Coverage','job','',j.id)}</td></tr>`).join('') || '<tr><td colspan="7">No scans yet. Add a connection to get started.</td></tr>'}</tbody></table></div></div>`;
}
async function accessPage() {
 if (!admin()) { $('#page-content').innerHTML = empty('Administrator access required','Your current role can view inventory, findings, and relationships. Administrators manage workspace access.'); return; }
 const [members,keys] = await Promise.all([api(route('members')),api(route('keys'))]);
 $('#page-content').innerHTML = `<div class="access-grid"><div class="card"><div class="card-head"><h2>Workspace members</h2>${button('Add member','add-member')}</div>${members.map(m => `<div class="row-item"><div class="grow"><strong>${e(m.email)}</strong><small>${e(m.role)}</small></div>${m.role !== 'owner' ? button('Remove','remove-member','',m.id) : pill('owner')}</div>`).join('')}</div><div class="card"><div class="card-head"><h2>Your API keys</h2>${button('Create key','create-key')}</div>${keys.map(k => `<div class="row-item"><div class="grow"><strong>${e(k.name)}</strong><small>Expires ${e(date(k.expires))}</small></div>${k.revoked ? pill('revoked') : button('Revoke','revoke-key','',k.id)}</div>`).join('') || '<div class="empty"><p>No API keys created. Keys are scoped to this workspace and expire after 90 days.</p></div>'}</div></div><div class="card"><div class="card-body"><h2>Roles, at a glance</h2><p class="fine"><strong>Viewer</strong> reads inventory and findings. <strong>Analyst</strong> also runs scans and imports reports. <strong>Admin</strong> manages connections, members, schedules, keys, and risk acceptance. <strong>Owner</strong> holds the initial workspace membership.</p><p class="fine">Adding a member shares this workspace with them. Existing users keep their password. Removing a membership immediately removes its access.</p></div></div>`;
}
async function activity() {
 if (!admin()) { $('#page-content').innerHTML = empty('Administrator access required','Workspace administrators can review the audit trail.'); return; }
 const rows = await api(route('audit'));
 $('#page-content').innerHTML = `<div class="card"><div class="table-scroll"><table><thead><tr><th>Action</th><th>Actor</th><th>Details</th><th>Time</th></tr></thead><tbody>${rows.map(a => `<tr><td><strong>${e(a.action)}</strong></td><td>${e(a.actor)}</td><td><small>${e(JSON.stringify(a.detail))}</small></td><td>${e(date(a.created))}</td></tr>`).join('')}</tbody></table></div></div><p class="fine">Latest 100 events shown. Retention is 30 days, capped at 10,000 events per workspace.</p>`;
}
function connectionForm() {
 modal(`<h2>Add a connection</h2><p>Start with a small collection scope. Credentials stay encrypted on this instance.</p><form id="connection-form"><label>Name<input name="name" maxlength="120" required placeholder="Production AWS"></label><label>Source<select name="kind" id="connection-kind"><option value="aws">AWS configuration metadata</option><option value="github">GitHub security alerts</option><option value="sarif">Upload SARIF repository reports</option><option value="demo">Synthetic demo data</option></select></label><div id="aws-fields"><label>Role ARN<input name="role_arn" placeholder="arn:aws:iam::123456789012:role/MayoCSPMReadOnly"></label><p class="fine">Create this connection first to obtain its external ID, then deploy the role from <a href="https://github.com/quentinmayo/MayoCSPM/blob/main/deploy/aws/read-only-role.yaml" target="_blank" rel="noopener">the CloudFormation template</a>. Validation happens when you run the first scan.</p><label>Regions (comma separated, up to four)<input name="regions" value="us-east-1"></label><div class="form-grid"><label>Maximum resources<input name="max_resources" type="number" min="1" max="5000" value="1000"></label><label>Logical API-call budget<input name="max_api_calls" type="number" min="10" max="1000" value="300"></label></div><label>Services (comma separated)<input name="services" value="ec2,s3,rds,iam,cloudtrail,eks"></label></div><div id="github-fields" hidden><label>Repository<input name="repository" placeholder="owner/repository"></label><label id="token-field">Fine-grained GitHub token<input name="token" type="password" autocomplete="off"></label><p class="fine">Alert synchronization uses GitHub's available security APIs; access depends on repository settings and plan. SARIF uploads do not require a token or clone.</p></div><button type="submit" class="primary">Create connection</button></form>`);
}
async function action(name,id) {
 if (name === 'refresh') return render();
 if (name === 'new-workspace') { modal('<h2>Create a workspace</h2><p>A workspace is the sharing boundary for your cloud inventory.</p><form id="workspace-form"><label>Name<input name="name" required maxlength="120" placeholder="My cloud"></label><button class="primary">Create workspace</button></form>'); return; }
 if (name === 'add-connection') return connectionForm();
 if (name === 'demo') { const c = await post(route('connections'),{name:'Example cloud · Synthetic',kind:'demo'}); await post(route(`connections/${c.id}/scan`)); page='jobs'; toast('Synthetic scan queued. No AWS credentials or API calls are used.'); return render(); }
 if (name === 'scan') { await post(route(`connections/${id}/scan`)); toast('Scan queued. The worker will collect only the configured metadata.'); page='jobs'; return render(); }
 if (name === 'schedule') { const c = connections.find(c => c.id == id); modal(`<h2>Scan schedule</h2><p>${e(c.name)} · Set 0 to pause. The minimum scheduled interval is one hour.</p><form id="schedule-form" data-id="${c.id}"><label>Interval in hours<input name="interval_hours" type="number" min="0" max="168" value="${c.interval_hours}" required></label><button class="primary">Save schedule</button></form>`); return; }
 if (name === 'upload') { modal(`<h2>Import SARIF</h2><p>SARIF 2.1.0 · Maximum 2 MiB and 1,000 results. Snippets, report messages, and matched secrets are discarded.</p><form id="upload-form" data-id="${id}"><label>Report<input type="file" name="file" accept=".sarif,.json" required></label><button class="primary">Import report</button></form>`); return; }
 if (name === 'filter-resources') { resourceFilters = {}; const q=$('#resource-search').value,kind=$('#kind-filter').value,region=$('#region-filter').value,tag=$('#tag-filter').value; if(q)resourceFilters.q=q; if(kind)resourceFilters.kind=kind; if(region)resourceFilters.region=region; if(tag){const index=tag.indexOf('='); resourceFilters.tag_key=index<0?tag:tag.slice(0,index); if(index>=0)resourceFilters.tag_value=tag.slice(index+1);} resourceOffset=0; return inventory(); }
 if (name === 'resource-next' || name === 'resource-prev') { resourceOffset += name.endsWith('next') ? 100 : -100; return inventory(); }
 if (name === 'finding-next' || name === 'finding-prev') { findingOffset += name.endsWith('next') ? 100 : -100; return findings(); }
 if (name === 'resource') { const rows = await api(route('resources?'+new URLSearchParams({...resourceFilters,offset:resourceOffset,limit:100}))); const r=rows.items.find(r=>r.id==id); if(!r)return; modal(`<h2>${e(r.name)}</h2><p>${e(r.kind)} · ${e(r.region)}</p><div class="details-list"><div><span>Resource ID</span>${e(r.uid)}</div><div><span>Observed</span>${e(date(r.seen))}</div></div><pre>${e(JSON.stringify(r.data,null,2))}</pre>`); return; }
 if (name === 'finding') { let rows=await api(route(`findings?status=${page==='overview'?'open':findingStatus}&offset=${page==='overview'?0:findingOffset}&limit=100`));const f=rows.items.find(f=>f.id==id);if(!f)return; modal(`<h2>${e(f.title)}</h2><p>${e(f.check_id)} · ${pill(f.severity)} · Risk ${f.score}</p><p>${e(f.resource_uid)}</p><h3>Evidence</h3><pre>${e(JSON.stringify(f.evidence,null,2))}</pre><h3>Why this priority</h3><p>${e(f.reasons.join(' · '))}</p><h3>Recommended next step</h3><p>${e(f.remediation)}</p><a href="${e(f.reference)}" target="_blank" rel="noopener">Rule reference ↗</a><p class="fine">Last observed ${e(date(f.last_seen))}. Missing resources or failed collectors do not resolve this finding.</p>${admin() && f.status !== 'resolved' ? `<form id="accept-form" data-id="${f.id}"><label>Risk acceptance reason<textarea name="reason" minlength="10" maxlength="1000" required></textarea></label><label>Expire after days<input name="days" type="number" min="1" max="90" value="7" required></label><button>Accept risk temporarily</button></form>` : ''}`); return; }
 if (name === 'job') { const j=(await api(route('jobs'))).find(j=>j.id==id);if(!j)return;modal(`<h2>Scan #${j.id}</h2><p>${pill(j.status)} · ${e(rel(j.created))}</p><p>${j.resource_count} resources · ${j.assessment.api_calls || 0} logical API calls (SDK retries may add attempts)</p>${j.error ? `<div class="notice">${e(j.error)}</div>` : ''}<pre>${e(JSON.stringify(j.coverage,null,2))}</pre><p class="fine">Unknown, limited, and uncollected scopes are not passes.</p>`);return; }
 if (name === 'add-member') { modal('<h2>Add a workspace member</h2><p>This shares this workspace’s inventory and findings with the specified account.</p><form id="member-form"><label>Email<input name="email" type="email" required></label><label>Role<select name="role"><option>viewer</option><option>analyst</option><option>admin</option></select></label><label>Initial password (new users only)<input name="password" type="password" minlength="14" maxlength="256" autocomplete="new-password"></label><button class="primary">Add member</button></form>');return; }
 if (name === 'remove-member') { if(!confirm('Remove this workspace membership?'))return;await api(route(`members/${id}`),{method:'DELETE'});return render(); }
 if (name === 'create-key') { modal('<h2>Create an API key</h2><p>The key inherits your current role in this workspace and expires after 90 days.</p><form id="key-form"><label>Name<input name="name" maxlength="80" required></label><button class="primary">Create key</button></form>');return; }
 if (name === 'revoke-key') { await api(route(`keys/${id}`),{method:'DELETE'});toast('API key revoked.');return render(); }
}
document.addEventListener('click', async event => {
 const target=event.target.closest('[data-action],[data-page]');if(!target)return;event.preventDefault();
 try { if(target.dataset.page){page=target.dataset.page;$('#dialog').close();$('.sidebar').classList.remove('open');await render();}else{target.disabled=true;await action(target.dataset.action,target.dataset.id);} } catch(error){toast(error.message);} finally{target.disabled=false;}
});
document.addEventListener('submit',async event=>{
 const form=event.target;if(!form.id.endsWith('-form'))return;event.preventDefault();const submit=form.querySelector('[type="submit"],button');submit.disabled=true;
 try { const data=Object.fromEntries(new FormData(form));
  if(form.id==='login-form'){await post('/api/auth/login',data);form.reset();await start();return;}
  if(form.id==='workspace-form'){const w=await post('/api/workspaces',data);workspace=w;await loadWorkspaces();}
  if(form.id==='connection-form'){
   const body={name:data.name,kind:data.kind};
   if(data.kind==='aws')Object.assign(body,{role_arn:data.role_arn,regions:data.regions.split(',').map(s=>s.trim()).filter(Boolean),services:data.services.split(',').map(s=>s.trim()).filter(Boolean),max_resources:Number(data.max_resources),max_api_calls:Number(data.max_api_calls)});
   if(['github','sarif'].includes(data.kind))body.repository=data.repository;
   if(data.kind==='github')body.token=data.token;
   const c=await post(route('connections'),body);form.reset();$('#dialog').close();page='connections';await render();
   if(c.kind==='aws')modal(`<h2>Complete the AWS role setup</h2><p>Use the role template with your operator role ARN and this server-generated external ID. Then choose Validate & scan.</p><pre>${e(c.external_id)}</pre><a href="https://github.com/quentinmayo/MayoCSPM/blob/main/docs/AWS.md" target="_blank" rel="noopener">AWS onboarding guide ↗</a>`);return;
  }
  if(form.id==='schedule-form')await api(route(`connections/${form.dataset.id}/schedule`),{method:'PUT',body:JSON.stringify({interval_hours:Number(data.interval_hours)})});
  if(form.id==='upload-form')await api(route(`connections/${form.dataset.id}/sarif`),{method:'POST',body:new FormData(form)});
  if(form.id==='member-form'){if(!data.password)delete data.password;await post(route('members'),data);}
  if(form.id==='accept-form')await post(route(`findings/${form.dataset.id}/accept`),{days:Number(data.days),reason:data.reason});
  if(form.id==='key-form'){const k=await post(route('keys'),data);modal(`<h2>Save your API key</h2><p>This key is shown once. Store it in your secret manager.</p><pre>${e(k.token)}</pre><p>Expires ${e(date(k.expires))}</p>`);return;}
  $('#dialog').close();toast('Saved.');await render();
 } catch(error){toast(error.message);}finally{submit.disabled=false;}
});
document.addEventListener('change',event=>{
 const target=event.target;
 if(target.id==='connection-kind'){$('#aws-fields').hidden=target.value!=='aws';$('#github-fields').hidden=!['github','sarif'].includes(target.value);$('#token-field').hidden=target.value!=='github';}
 if(target.id==='finding-status'){findingStatus=target.value;findingOffset=0;findings().catch(error=>toast(error.message));}
 if(target.id==='workspace-picker'){workspace=allWorkspaces.find(w=>w.id==target.value);resourceOffset=0;findingOffset=0;resourceFilters={};$('#role').textContent=workspace.role;render();}
});
$('#dialog .dialog-close').onclick=()=>{$('#dialog').close();$('#dialog-body').textContent='';};
$('#dialog').addEventListener('close',()=>{$('#dialog-body').textContent='';});
$('#mobile-menu').onclick=()=>$('.sidebar').classList.toggle('open');
$('#new-workspace').onclick=()=>action('new-workspace');
$('#logout').onclick=async()=>{try{await post('/api/auth/logout');}finally{showLogin();}};
start();

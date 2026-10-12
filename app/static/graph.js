'use strict';
/* Shared bounded SVG explorer; graph values are text, never executable markup. */
window.MayoGraph = (() => {
 let sequence = 0;
 const esc = value => { const el=document.createElement('span');el.textContent=String(value ?? '');return el.innerHTML.replaceAll('"','&quot;').replaceAll("'",'&#39;'); };
 const short = (value,n=24) => String(value ?? '').length>n ? String(value).slice(0,n-1)+'…' : String(value ?? '');
 function render(host, original, options={}) {
  const uid='graph-'+(++sequence), initial=original;
  let data=original, selected=null, highlighted=new Set(), serial=0, zoom=1, pan={x:0,y:0};
  const live=()=>host.isConnected && (!options.active || options.active());
  const notice=g=>`${g.truncated ? '<strong>Partial graph.</strong> '+esc((g.warnings||[]).join(', '))+'. ' : ''}${(g.coverage||[]).some(c=>c.gap_count) ? 'Collection gaps are present. ' : ''}Configuration evidence does not prove reachability or transitive access.`;
  host.innerHTML=`<div class="graph-explorer"><div class="graph-tools"><label>Find a node<input data-g="search" type="search" placeholder="Name, type or identifier"></label><label>Type<select data-g="type"><option value="">All types</option></select></label><div class="graph-zoom"><button data-g="minus" aria-label="Zoom out">−</button><button data-g="plus" aria-label="Zoom in">+</button><button data-g="fit">Fit</button><button data-g="reset">All results</button></div></div><div class="graph-legend"><span><i class="observed"></i>Observed configuration</span><span><i class="candidate"></i>Candidate exposure</span><span><i class="declared"></i>Declared association</span><span>Arrows show the relationship direction</span></div><p class="fine graph-notice" role="status"></p><div class="graph-layout"><div class="graph-canvas"><svg viewBox="0 0 1100 620" aria-label="Interactive cloud relationship graph"><defs><marker id="${uid}-arrow" markerWidth="8" markerHeight="8" refX="8" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8" class="arrow-head"/></marker></defs><g class="graph-scene"></g></svg><p class="graph-hint">Select a node or connection · Drag the background to pan · Use + / − to zoom</p><details class="graph-node-list"><summary>Accessible node list</summary><div></div></details></div><aside class="graph-inspector" aria-live="polite"><h3>Follow the evidence</h3><p>Select a resource to inspect its public configuration and neighboring services.</p><p class="fine">A bucket’s public policy and safeguards explain potential exposure. A workload attachment or log destination describes a dependency; it does not establish an attack.</p></aside></div></div>`;
  const q=s=>host.querySelector(s), svg=q('svg'), scene=q('.graph-scene'), inspector=q('.graph-inspector');
  function transform(){scene.setAttribute('transform',`translate(${pan.x} ${pan.y}) scale(${zoom})`);}
  function draw(){
   const term=q('[data-g="search"]').value.toLowerCase(), type=q('[data-g="type"]').value;
   const matches=data.nodes.filter(n=>(!type||n.kind===type)&&(!term||[n.name,n.kind,n.uid,n.id].join(' ').toLowerCase().includes(term)));
   const ordered=[...matches].sort((a,b)=>(a.id===selected?-1:b.id===selected?1:0)||(a.entity==='Internet'?-1:b.entity==='Internet'?1:0)||a.id.localeCompare(b.id));
   const nodes=ordered.slice(0,100), ids=new Set(nodes.map(n=>n.id));
   const edges=data.edges.filter(e=>ids.has(e.source)&&ids.has(e.target)).slice(0,200);
   const levels=new Map(), incoming=new Map(nodes.map(n=>[n.id,0]));
   edges.forEach(e=>incoming.set(e.target,(incoming.get(e.target)||0)+1));
   const roots=nodes.filter(n=>n.entity==='Internet'||!incoming.get(n.id));
   roots.forEach(n=>levels.set(n.id,0));
   const queue=roots.map(n=>n.id);
   for(let cursor=0;cursor<queue.length;cursor++)for(const edge of edges.filter(e=>e.source===queue[cursor])){
    levels.set(edge.target,Math.min(3,Math.max(levels.get(edge.target)||0,levels.get(edge.source)+1)));
    incoming.set(edge.target,incoming.get(edge.target)-1);if(!incoming.get(edge.target))queue.push(edge.target);
   }
   const groups=[[],[],[],[]];nodes.forEach(n=>groups[levels.get(n.id)??1].push(n));
   const positions=new Map(), height=Math.max(620,Math.max(...groups.map(g=>g.length))*104+90);
   const last=groups.reduce((value,g,index)=>g.length?index:value,0), width=Math.max(600,(last+1)*276+30);
   svg.setAttribute('viewBox',`0 0 ${width} ${height}`);
   groups.forEach((group,column)=>group.forEach((n,row)=>positions.set(n.id,{x:30+column*276,y:45+row*(height-80)/Math.max(1,group.length)})));
   scene.innerHTML=edges.map(edge=>{const a=positions.get(edge.source),b=positions.get(edge.target);return `<g class="graph-edge ${esc(edge.confidence)} ${highlighted.has(edge.id)?'highlighted':''}" data-edge="${esc(edge.id)}" tabindex="0" role="button" aria-label="${esc(edge.relation+'; '+edge.confidence)}"><path d="M${a.x+220},${a.y+34} C${a.x+260},${a.y+34} ${b.x-40},${b.y+34} ${b.x},${b.y+34}" marker-end="url(#${uid}-arrow)"/><path class="edge-hit" d="M${a.x+220},${a.y+34} C${a.x+260},${a.y+34} ${b.x-40},${b.y+34} ${b.x},${b.y+34}"/></g>`;}).join('')+nodes.map(n=>{const p=positions.get(n.id);return `<g class="graph-node ${n.exposure==='potential'?'potential':''} ${n.entity==='Finding'?'finding-node':''} ${selected===n.id?'selected':''}" data-node="${esc(n.id)}" transform="translate(${p.x},${p.y})" tabindex="0" role="button" aria-label="${esc([n.name,n.kind||n.entity,n.exposure||n.severity].filter(Boolean).join(', '))}"><title>${esc(n.uid||n.name)}</title><rect width="220" height="76" rx="12"/><text x="14" y="22" class="node-kind">${esc(short(n.kind||n.entity,31))}</text><text x="14" y="43" class="node-title">${esc(short(n.name,26))}</text><text x="14" y="62" class="node-meta">${esc(n.entity==='Finding'?n.severity+' · '+n.status:n.entity==='Internet'?'Public configuration origin':n.exposure==='potential'?'Potential exposure':n.exposure==='unknown'?'Exposure unknown':(n.finding_count||0)+' open findings in graph')}</text></g>`;}).join('');
   q('.graph-notice').innerHTML=notice(data)+(matches.length>100?' Showing 100 of '+matches.length+' matching nodes; narrow the search.':'')+(!nodes.length?' No matching nodes in this bounded result.':'');
   q('.graph-node-list div').innerHTML=nodes.map(n=>`<button data-node="${esc(n.id)}">${esc(n.name)} · ${esc(n.kind||n.entity)}</button>`).join('');
   transform();
  }
  function refreshTypes(){const current=q('[data-g="type"]').value;q('[data-g="type"]').innerHTML='<option value="">All types</option>'+[...new Set(data.nodes.map(n=>n.kind).filter(Boolean))].sort().map(k=>`<option value="${esc(k)}">${esc(k)}</option>`).join('');q('[data-g="type"]').value=current;}
  function nodeName(id){return data.nodes.find(n=>n.id===id)?.name||initial.nodes.find(n=>n.id===id)?.name||id;}
  function edgeDetails(edge){inspector.innerHTML=`<h3>${esc(edge.relation)}</h3><p>${esc(nodeName(edge.source))} → ${esc(nodeName(edge.target))}</p><span class="chip">${esc(edge.confidence)}</span><h4>Evidence</h4><pre>${esc(JSON.stringify(edge.evidence,null,2))}</pre><p class="fine">${esc(edge.limitations)}</p>`;}
  async function inspect(id, explore=false){
   const node=data.nodes.find(n=>n.id===id);if(!node)return;
   selected=id;highlighted.clear();draw();
   const connected=data.edges.filter(e=>e.source===id||e.target===id);
   inspector.innerHTML=`<h3>${esc(node.name)}</h3><p class="fine">${esc(node.kind||node.entity)} · ${esc(node.region||'')}</p><code class="graph-id">${esc(node.uid||node.id)}</code>${node.exposure?`<p>Public configuration: <strong>${esc(node.exposure.replace('_',' '))}</strong></p>`:''}${node.severity?`<p>${esc(node.severity)} · ${esc(node.status)} · Risk ${esc(node.score)}</p>`:''}<h4>Evidence</h4><pre>${esc(JSON.stringify(node.exposure_evidence||node.evidence||{observed_at:node.seen||node.last_seen},null,2))}</pre><p class="fine">${esc(node.limitations||'Finding evidence retains its own observation time.')}</p><h4>Explore dependency context</h4><div class="graph-context-controls"><label>Direction<select data-g="direction"><option value="both">Both directions</option><option value="out">Outgoing relationships</option><option value="in">Incoming relationships</option></select></label><label>Hops<select data-g="depth"><option>1</option><option selected>2</option><option>3</option><option>4</option></select></label><button data-g="context" class="primary">Explore connections</button></div><p class="fine">A relationship’s direction describes configuration, not the direction of an exploit.</p><div class="graph-context-result"></div><h4>Visible relationships (${connected.length})</h4>${connected.slice(0,30).map(edge=>`<button class="graph-neighbor" data-edge="${esc(edge.id)}">${esc(edge.source===id?'→ '+nodeName(edge.target):'← '+nodeName(edge.source))}<small>${esc(edge.relation)} · ${esc(edge.confidence)}</small></button>`).join('')||'<p class="fine">No relationships in this result. Missing connections do not prove isolation.</p>'}`;
   if(explore)await context();
  }
  async function context(){
   if(!options.endpoint)return;
   const ticket=++serial, id=selected, direction=q('[data-g="direction"]').value, depth=q('[data-g="depth"]').value;
   const box=q('.graph-context-result');box.textContent='Loading current evidence…';
   try{
    const result=await options.api(options.endpoint+'/context?'+new URLSearchParams({node_id:id,direction,depth}));
    if(!live()||ticket!==serial||selected!==id)return;
    data=result;refreshTypes();draw();
    box.innerHTML=`<p class="fine">${esc(result.interpretation)}</p><h4>Candidate paths from Internet (${result.paths.length}${result.warnings.includes('path_limit')?' · partial':''})</h4>${result.paths.map((p,i)=>`<button class="graph-path" data-path="${i}">${p.nodes.map(nodeName).map(esc).join(' → ')}<small>${p.length} relationships · configuration only</small></button>`).join('')||'<p class="fine">No path found within the collected evidence and limits. This does not establish that the resource is private.</p>'}`;
   }catch(error){if(live()&&ticket===serial)box.textContent=error.message;}
  }
  host.addEventListener('input',event=>{if(event.target.matches('[data-g="search"]'))draw();});
  host.addEventListener('change',event=>{if(event.target.matches('[data-g="type"]'))draw();});
  async function handle(event){
   const target=event.target.closest('[data-node],[data-edge],[data-g],[data-path]');if(!target)return;
   if(event.type==='keydown'&&!['Enter',' '].includes(event.key))return;
   if(event.type==='keydown')event.preventDefault();
   if(target.dataset.node){serial++;await inspect(target.dataset.node);return;}
   if(target.dataset.edge){const edge=data.edges.find(e=>e.id===target.dataset.edge);if(edge)edgeDetails(edge);return;}
   if(target.dataset.path!==undefined){highlighted=new Set(data.paths[Number(target.dataset.path)].edges);draw();return;}
   const action=target.dataset.g;
   if(action==='context')await context();
   if(action==='plus'||action==='minus'){zoom=Math.max(.35,Math.min(3,zoom*(action==='plus'?1.2:1/1.2)));transform();}
   if(action==='fit'){zoom=1;pan={x:0,y:0};transform();}
   if(action==='reset'){serial++;data=initial;selected=null;highlighted.clear();q('[data-g="search"]').value='';refreshTypes();draw();inspector.innerHTML='<h3>Follow the evidence</h3><p>Select a resource or connection.</p>';}
  }
  host.addEventListener('click',handle);host.addEventListener('keydown',handle);
  let drag;
  svg.addEventListener('pointerdown',event=>{if(event.target.closest('[data-node],[data-edge]'))return;drag={x:event.clientX,y:event.clientY,pan:{...pan}};svg.setPointerCapture(event.pointerId);});
  svg.addEventListener('pointermove',event=>{if(!drag)return;const scale=svg.viewBox.baseVal.width/svg.getBoundingClientRect().width;pan={x:drag.pan.x+(event.clientX-drag.x)*scale,y:drag.pan.y+(event.clientY-drag.y)*scale};transform();});
  svg.addEventListener('pointerup',()=>drag=null);svg.addEventListener('pointercancel',()=>drag=null);
  refreshTypes();draw();
 }
 return {render};
})();

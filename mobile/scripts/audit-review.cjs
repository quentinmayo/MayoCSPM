// Temporary, explicit exceptions for unfixed upstream build tooling advisories.
const { spawnSync } = require('node:child_process');
const exceptions = new Set(['GHSA-vfj7-8cjw-p6xm', 'GHSA-86w9-cpqp-85rv']);
const expires = Date.parse('2026-11-11T00:00:00Z');
const result = spawnSync('npm', ['audit', '--json'], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
let audit;
try { audit = JSON.parse(result.stdout); } catch { console.error('Dependency audit did not return valid JSON.'); process.exit(1); }
if (result.error || audit.error || !audit.metadata || !audit.vulnerabilities) { console.error('Dependency audit failed.'); process.exit(1); }
const seen = new Set();
let unexpected = false;
for (const row of Object.values(audit.vulnerabilities)) {
  for (const item of row.via) {
    if (typeof item === 'string') continue;
    const id = item.url?.split('/').pop();
    if (seen.has(id)) continue;
    seen.add(id);
    if (!exceptions.has(id) || Date.now() >= expires) {
      console.error(`Unreviewed/expired advisory: ${id} (${item.severity}) ${item.title}`); unexpected = true;
    } else console.warn(`Known upstream build-tool advisory: ${id}; exception expires 2026-11-11. See docs/MOBILE.md.`);
  }
}
console.log(`${seen.size} root advisories; ${unexpected ? 'review required' : 'no additional advisories'}.`);
process.exit(unexpected ? 1 : 0);

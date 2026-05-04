import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3030;
const DATA_ROOT = process.env.RA_DATA_ROOT || (fs.existsSync('D:/') ? 'D:/SovereignRA' : path.join(__dirname, 'data'));
const PRIVATE_DIR = path.join(DATA_ROOT, 'data', 'private');
const LOG_DIR = path.join(DATA_ROOT, 'logs');
fs.mkdirSync(PRIVATE_DIR, { recursive: true });
fs.mkdirSync(LOG_DIR, { recursive: true });

app.use(express.json({ limit: '30mb' }));
app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0 }));
app.use((req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

const graphFile = path.join(PRIVATE_DIR, 'graph.json');
const auditFile = path.join(LOG_DIR, 'sovereign_audit.jsonl');
const settingsFile = path.join(PRIVATE_DIR, 'settings.json');
const uploadsDir = path.join(PRIVATE_DIR, 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });

function sha256(x) { return crypto.createHash('sha256').update(String(x)).digest('hex'); }
function readJson(file, fallback) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; } }
function writeJson(file, data) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(data, null, 2)); }
function safeText(x) { return String(x || '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200000); }

function defaultGraph() {
  return [
    { id: 'NODE-RA-001', claim: 'Verified AI Operations routes AI output through verification before operational trust.', tags: ['verified-ai-operations','method','ra'], status: 'rooted' },
    { id: 'NODE-RA-002', claim: 'Completion language must be blocked unless completion proof exists.', tags: ['completion-proof','false-completion'], status: 'rooted' },
    { id: 'NODE-RA-003', claim: 'User-owned local storage is the default privacy posture.', tags: ['privacy','local-storage','D-drive'], status: 'rooted' },
    { id: 'NODE-RA-004', claim: 'Unverified answers should still be returned with a clear Not Verified badge when safe.', tags: ['verification','ux'], status: 'rooted' },
    { id: 'NODE-RA-005', claim: 'Hosted models are candidate generators, not final truth authorities.', tags: ['hosted-ai','ra-refinery'], status: 'rooted' },
    { id: 'NODE-RA-006', claim: 'Robots require task state, authority, sensor evidence, safety envelope, abort path, completion proof, and audit record before physical action.', tags: ['robotics','safety','baseline'], status: 'rooted' }
  ];
}

function getGraph() {
  const g = readJson(graphFile, null);
  if (Array.isArray(g) && g.length) return g;
  const seed = defaultGraph();
  writeJson(graphFile, seed);
  return seed;
}

function getSettings() {
  const defaults = {
    theme: 'resolution_assurance_blue',
    provider: 'anthropic',
    providerLabel: 'Claude',
    fallbackProvider: 'ollama',
    retrievalBudgetMs: 1800,
    modelTimeoutMs: 8000,
    stream: true,
    localStorageRoot: DATA_ROOT,
    allowUnverifiedAnswer: true,
    blockFalseCompletion: true,
    fastMode: true
  };
  return { ...defaults, ...readJson(settingsFile, {}) };
}

function audit(event) {
  let prevHash = 'GENESIS';
  try {
    const lines = fs.readFileSync(auditFile, 'utf8').trim().split(/\r?\n/).filter(Boolean);
    if (lines.length) prevHash = JSON.parse(lines[lines.length - 1]).hash || prevHash;
  } catch {}
  const record = { ts: new Date().toISOString(), prevHash, ...event };
  record.hash = sha256(JSON.stringify(record));
  fs.appendFileSync(auditFile, JSON.stringify(record) + '\n');
  return record;
}

function searchGraph(query, limit = 8) {
  const q = String(query || '').toLowerCase().split(/\W+/).filter(Boolean);
  if (!q.length) return getGraph().slice(0, limit);
  return getGraph()
    .map(n => {
      const hay = `${n.id} ${n.claim} ${(n.tags||[]).join(' ')}`.toLowerCase();
      const score = q.reduce((a,t) => a + (hay.includes(t) ? 1 : 0), 0);
      return { ...n, score };
    })
    .filter(n => n.score > 0)
    .sort((a,b) => b.score - a.score)
    .slice(0, limit);
}

function refine(question, draft, evidence) {
  const text = `${question} ${draft}`;
  const highImpact = /value|valuation|breach|legal|refund|compensation|robot|dose|cut|heat|lift|transport|completed|done|fixed|sealed|wired|located|tested/i.test(text);
  const completionClaim = /\b(done|completed|fixed|sealed|wired|located|tested|fully operational)\b/i.test(draft);
  let status = 'Not Verified';
  let grade = 'F';
  if (evidence.length >= 3 && !completionClaim) { status = 'Verified'; grade = 'A'; }
  else if (evidence.length >= 1 && !completionClaim) { status = 'Partially Verified'; grade = 'C'; }
  if (completionClaim && !evidence.some(e => /completion|audit|proof/i.test((e.tags||[]).join(' ') + e.claim))) {
    status = 'Action Not Completed'; grade = 'F';
  }
  if (highImpact && evidence.length < 2) { status = completionClaim ? 'Action Not Completed' : 'Not Verified'; grade = 'F'; }
  return { status, grade, evidenceIds: evidence.map(e => e.id), unverified: status !== 'Verified' };
}

function localAnswer(question, evidence, reason = '') {
  const evidenceText = evidence.map(e => `- ${e.id}: ${e.claim}`).join('\n') || '- No matching local evidence nodes.';
  return `${reason ? reason + '\n\n' : ''}I can answer from the local Resolution Assurance layer.\n\n${evidenceText}\n\nAnswer:\n${question}\n\nStatus note: this response is labelled by RA Refinery based on available local evidence.`;
}

async function claudeAnswer(question, evidence) {
  const key = process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY;
  if (!key) return null;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Number(getSettings().modelTimeoutMs || 8000));
  const evidenceText = evidence.map(e => `- ${e.id}: ${e.claim}`).join('\n') || 'No matching local evidence nodes.';
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST', signal: controller.signal,
      headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: process.env.RA_MODEL || 'claude-3-5-sonnet-latest', max_tokens: 900,
        system: 'You are Resolution AI. Answer like a normal helpful chatbot. Do not claim done/fixed/completed unless evidence proves it. If evidence is weak, answer but acknowledge uncertainty.',
        messages: [{ role: 'user', content: `Question:\n${question}\n\nLocal evidence:\n${evidenceText}` }]
      })
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return localAnswer(question, evidence, `Claude provider returned ${r.status}. Falling back locally.`);
    return (j.content || []).map(c => c.text || '').join('\n').trim() || localAnswer(question, evidence, 'Claude returned empty output. Falling back locally.');
  } catch (err) {
    return localAnswer(question, evidence, `Claude timed out or failed (${err.name || 'error'}). Falling back locally.`);
  } finally { clearTimeout(timeout); }
}

async function draftAnswer(question, evidence) {
  return await claudeAnswer(question, evidence) || localAnswer(question, evidence);
}

app.get('/api/status', (req, res) => res.json({ ok: true, app: 'Resolution AI / Sovereign Reality Engine', version: '0.3.0-blue-working', port: PORT, provider: (process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY) ? 'Claude / Anthropic' : 'Local evidence fallback', dataRoot: DATA_ROOT, settings: getSettings() }));
app.get('/api/settings', (req, res) => res.json(getSettings()));
app.post('/api/settings', (req, res) => { const next = { ...getSettings(), ...(req.body || {}) }; writeJson(settingsFile, next); const aud = audit({ type: 'settings_update', settingsHash: sha256(JSON.stringify(next)) }); res.json({ ok: true, settings: next, audit: aud.hash }); });

app.post('/api/chat', async (req, res) => {
  const question = safeText(req.body?.message || req.body?.question).trim();
  if (!question) return res.status(400).json({ error: 'message required' });
  const trace = [{ step: 'classify', status: 'ok' }];
  const evidence = searchGraph(question, getSettings().maxGraphNodes || 8);
  trace.push({ step: 'graph', status: 'ok', count: evidence.length });
  const draft = await draftAnswer(question, evidence);
  trace.push({ step: 'model', status: (process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY) ? 'claude_or_fallback' : 'local_fallback' });
  const verification = refine(question, draft, evidence);
  trace.push({ step: 'ra_refinery', status: verification.status, grade: verification.grade });
  const aud = audit({ type: 'chat', questionHash: sha256(question), verification, evidenceIds: verification.evidenceIds });
  res.json({ answer: draft, verification, trace, audit: { id: aud.hash, prevHash: aud.prevHash }, evidence });
});

app.get('/api/graph/search', (req, res) => res.json({ results: searchGraph(String(req.query.q || ''), Number(req.query.limit || 20)) }));
app.post('/api/graph/anchor', (req, res) => { const graph = getGraph(); const node = { id: req.body?.id || `NODE-${Date.now()}`, claim: safeText(req.body?.claim), tags: req.body?.tags || [], status: 'rooted', createdAt: new Date().toISOString() }; graph.push(node); writeJson(graphFile, graph); const aud = audit({ type: 'graph_anchor', nodeId: node.id, claimHash: sha256(node.claim) }); res.json({ node, audit: aud.hash }); });
app.get('/api/audit', (req, res) => { try { res.type('text/plain').send(fs.readFileSync(auditFile, 'utf8')); } catch { res.type('text/plain').send(''); } });
app.get('/api/legal', (req, res) => res.json({ privacy: 'Local-first storage. Hosted provider use is optional and outputs are candidate material until verified.', terms: 'Prototype method documentation for Verified AI Operations. Human review required for high-impact decisions.', acceptableUse: 'Do not use for unlawful access, unsafe physical action, or unsupported completion claims.', verification: 'Every answer receives Verified, Partially Verified, Not Verified, Insufficient Evidence, Action Not Completed, or Refused for Safety.' }));
app.post('/api/upload', (req, res) => { const name = String(req.body?.name || `upload-${Date.now()}.txt`).replace(/[\\/:*?"<>|]/g, '_'); const content = safeText(req.body?.content || ''); const file = path.join(uploadsDir, name); fs.writeFileSync(file, content); const h = sha256(content); const node = { id: `UPLOAD-${Date.now()}`, claim: `Uploaded local text file ${name}`, tags: ['upload','local'], status: 'rooted', sha256: h, path: file }; const graph = getGraph(); graph.push(node); writeJson(graphFile, graph); const aud = audit({ type: 'upload', file: name, sha256: h }); res.json({ ok: true, file, node, audit: aud.hash }); });

app.listen(PORT, () => console.log(`Resolution AI running at http://localhost:${PORT}`));

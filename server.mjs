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

app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const graphFile = path.join(PRIVATE_DIR, 'graph.json');
const auditFile = path.join(LOG_DIR, 'sovereign_audit.jsonl');
const settingsFile = path.join(PRIVATE_DIR, 'settings.json');

function sha256(x) { return crypto.createHash('sha256').update(String(x)).digest('hex'); }
function readJson(file, fallback) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; } }
function writeJson(file, data) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(data, null, 2)); }

function defaultGraph() {
  return [
    { id: 'NODE-RA-001', claim: 'Verified AI Operations routes AI output through verification before operational trust.', tags: ['verified-ai-operations','method','ra'], status: 'rooted' },
    { id: 'NODE-RA-002', claim: 'Completion language must be blocked unless completion proof exists.', tags: ['completion-proof','false-completion'], status: 'rooted' },
    { id: 'NODE-RA-003', claim: 'User-owned local storage is the default privacy posture.', tags: ['privacy','local-storage','D-drive'], status: 'rooted' },
    { id: 'NODE-RA-004', claim: 'Unverified answers should still be returned with a clear Not Verified badge when safe.', tags: ['verification','ux'], status: 'rooted' },
    { id: 'NODE-RA-005', claim: 'Hosted models are candidate generators, not final truth authorities.', tags: ['hosted-ai','ra-refinery'], status: 'rooted' }
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
    fallbackProvider: 'ollama',
    retrievalBudgetMs: 1800,
    stream: true,
    localStorageRoot: DATA_ROOT,
    allowUnverifiedAnswer: true,
    blockFalseCompletion: true
  };
  const s = readJson(settingsFile, {});
  return { ...defaults, ...s };
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
  const q = query.toLowerCase().split(/\W+/).filter(Boolean);
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
  const highImpact = /value|valuation|breach|legal|refund|compensation|robot|dose|cut|heat|lift|transport|completed|done|fixed|sealed|wired|located|tested/i.test(question + ' ' + draft);
  const completionClaim = /\b(done|completed|fixed|sealed|wired|located|tested|fully operational)\b/i.test(draft);
  let status = 'Not Verified';
  let grade = 'F';
  if (evidence.length >= 3 && !completionClaim) { status = 'Verified'; grade = 'A'; }
  else if (evidence.length >= 1 && !completionClaim) { status = 'Partially Verified'; grade = 'C'; }
  if (completionClaim && !evidence.some(e => /completion|audit|proof/i.test((e.tags||[]).join(' ') + e.claim))) {
    status = 'Action Not Completed'; grade = 'F';
  }
  if (highImpact && evidence.length < 2) {
    status = completionClaim ? 'Action Not Completed' : 'Not Verified';
    grade = 'F';
  }
  return { status, grade, evidenceIds: evidence.map(e => e.id), unverified: status !== 'Verified' };
}

async function draftAnswer(question, evidence) {
  const key = process.env.ANTHROPIC_API_KEY;
  const evidenceText = evidence.map(e => `- ${e.id}: ${e.claim}`).join('\n') || 'No matching local evidence nodes.';
  const system = 'You are Resolution AI. Answer helpfully like a normal chatbot. Do not claim done/fixed/completed unless evidence proves it. Use provided evidence when relevant. If not verified, still answer but acknowledge uncertainty.';
  if (key) {
    try {
      const { Anthropic } = await import('@anthropic-ai/sdk');
      const client = new Anthropic({ apiKey: key });
      const msg = await client.messages.create({
        model: process.env.RA_MODEL || 'claude-3-5-sonnet-latest',
        max_tokens: 900,
        system,
        messages: [{ role: 'user', content: `Question:\n${question}\n\nLocal evidence:\n${evidenceText}` }]
      });
      return msg.content?.map(c => c.text || '').join('\n').trim() || 'No model output returned.';
    } catch (err) {
      return `Claude provider failed locally: ${err.message}. Based on local evidence: ${evidenceText}`;
    }
  }
  return `I can answer from the local Resolution Assurance graph only because no Claude key is available in this runtime.\n\nLocal evidence found:\n${evidenceText}\n\nAnswer: ${question}\n\nThis should be treated as a local, limited answer until Claude or Ollama is connected.`;
}

app.get('/api/status', (req, res) => {
  res.json({ ok: true, app: 'Resolution AI / Sovereign Reality Engine', port: PORT, provider: process.env.ANTHROPIC_API_KEY ? 'Claude / Anthropic' : 'Local evidence fallback', dataRoot: DATA_ROOT, settings: getSettings() });
});

app.post('/api/chat', async (req, res) => {
  const question = String(req.body?.message || req.body?.question || '').trim();
  if (!question) return res.status(400).json({ error: 'message required' });
  const trace = [];
  trace.push({ step: 'classify', status: 'ok', detail: 'fast verified pipeline' });
  const evidence = searchGraph(question, getSettings().maxGraphNodes || 8);
  trace.push({ step: 'graph', status: 'ok', count: evidence.length });
  const draft = await draftAnswer(question, evidence);
  trace.push({ step: 'model', status: process.env.ANTHROPIC_API_KEY ? 'claude' : 'local_fallback' });
  const verification = refine(question, draft, evidence);
  trace.push({ step: 'ra_refinery', status: verification.status, grade: verification.grade });
  const aud = audit({ type: 'chat', questionHash: sha256(question), verification, evidenceIds: verification.evidenceIds });
  res.json({ answer: draft, verification, trace, audit: { id: aud.hash, prevHash: aud.prevHash }, evidence });
});

app.get('/api/graph/search', (req, res) => res.json({ results: searchGraph(String(req.query.q || ''), Number(req.query.limit || 20)) }));
app.post('/api/graph/anchor', (req, res) => {
  const body = req.body || {};
  const graph = getGraph();
  const node = { id: body.id || `NODE-${Date.now()}`, claim: String(body.claim || ''), tags: body.tags || [], status: 'rooted', createdAt: new Date().toISOString() };
  graph.push(node); writeJson(graphFile, graph); const aud = audit({ type: 'graph_anchor', nodeId: node.id, claimHash: sha256(node.claim) }); res.json({ node, audit: aud.hash });
});
app.get('/api/audit', (req, res) => { try { res.type('text/plain').send(fs.readFileSync(auditFile, 'utf8')); } catch { res.type('text/plain').send(''); } });

app.listen(PORT, () => console.log(`Resolution AI running at http://localhost:${PORT}`));

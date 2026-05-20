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

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});
app.use(express.json({ limit: '30mb' }));
app.use(express.static(path.join(__dirname, 'public'), { etag: false, maxAge: 0, lastModified: false }));

const graphFile = path.join(PRIVATE_DIR, 'graph.json');
const auditFile = path.join(LOG_DIR, 'sovereign_audit.jsonl');
const documentsFile = path.join(PRIVATE_DIR, 'documents.json');
const documentIndexFile = path.join(LOG_DIR, 'document_index.jsonl');
const quarantineFile = path.join(LOG_DIR, 'quarantine.jsonl');
const settingsFile = path.join(PRIVATE_DIR, 'settings.json');
const uploadsDir = path.join(PRIVATE_DIR, 'uploads');
fs.mkdirSync(uploadsDir, { recursive: true });

function sha256(x) { return crypto.createHash('sha256').update(String(x)).digest('hex'); }
function readJson(file, fallback) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; } }
function writeJson(file, data) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, JSON.stringify(data, null, 2)); }
function safeText(x) { return String(x || '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200000); }
function cleanDocumentText(x) { return String(x || '').replace(/\u0000/g, '').slice(0, 400000); }
function appendJsonl(file, data) { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.appendFileSync(file, JSON.stringify(data) + '\n'); }

function buildSnippet(text, terms, maxLength = 240) {
  const source = cleanDocumentText(text).replace(/\s+/g, ' ').trim();
  if (!source) return 'No readable text could be indexed.';
  const haystack = source.toLowerCase();
  const hitIndex = terms.reduce((best, term) => {
    const idx = haystack.indexOf(term);
    return idx >= 0 && (best < 0 || idx < best) ? idx : best;
  }, -1);
  const start = hitIndex >= 0 ? Math.max(0, hitIndex - 80) : 0;
  const end = Math.min(source.length, start + maxLength);
  const snippet = source.slice(start, end);
  return start > 0 ? `...${snippet}` : snippet;
}

function loadDocuments() {
  const docs = readJson(documentsFile, null);
  if (Array.isArray(docs)) return docs;
  writeJson(documentsFile, []);
  return [];
}

function saveDocuments(documents) {
  writeJson(documentsFile, Array.isArray(documents) ? documents.slice(0, 500) : []);
}

function scanDocument({ name, mime, text, source }) {
  const sample = String(text || '').slice(0, 200000);
  const rules = [
    { id: 'script-tag', severity: 'high', pattern: /<script\b[\s\S]*?>/i, message: 'Script tag detected' },
    { id: 'javascript-url', severity: 'high', pattern: /javascript:/i, message: 'javascript: URL detected' },
    { id: 'html-event-handler', severity: 'high', pattern: /\son[a-z]+\s*=/i, message: 'Inline HTML event handler detected' },
    { id: 'shell-exec', severity: 'high', pattern: /\b(?:rm\s+-rf|curl\s+https?:\/\/|wget\s+https?:\/\/|Invoke-WebRequest|Invoke-Expression|powershell(?:\.exe)?|cmd(?:\.exe)?\s+\/c|bash\s+-c|sh\s+-c)\b/i, message: 'Executable shell instruction detected' },
    { id: 'dynamic-eval', severity: 'high', pattern: /\b(?:eval|Function)\s*\(/i, message: 'Dynamic code evaluation detected' },
    { id: 'private-key', severity: 'high', pattern: /BEGIN (?:RSA|OPENSSH|PRIVATE) KEY/i, message: 'Private key material detected' },
    { id: 'credential', severity: 'medium', pattern: /\b(?:api[_-]?key|secret|password|token|bearer)\b/i, message: 'Credential-like content detected' },
    { id: 'base64-payload', severity: 'medium', pattern: /\b[A-Za-z0-9+/]{120,}={0,2}\b/, message: 'Long base64 payload detected' },
    { id: 'remote-url', severity: 'medium', pattern: /\bhttps?:\/\/[^\s<>()]{8,}\b/i, message: 'External URL detected' }
  ];

  const issues = [];
  for (const rule of rules) {
    if (rule.pattern.test(sample)) {
      issues.push({ id: rule.id, severity: rule.severity, message: rule.message });
    }
  }

  const hasHighRisk = issues.some((issue) => issue.severity === 'high');
  const hasMediumRisk = issues.some((issue) => issue.severity === 'medium');
  const status = hasHighRisk ? 'quarantined' : hasMediumRisk ? 'review' : 'clean';

  return {
    status,
    safe: status !== 'quarantined',
    reviewedAt: new Date().toISOString(),
    name: String(name || 'Uploaded document'),
    mime: String(mime || 'text/plain'),
    source: String(source || 'upload'),
    issues
  };
}

function buildDocumentRecord({ name, source, mime, content, path: filePath }) {
  const text = cleanDocumentText(content);
  const scan = scanDocument({ name, mime, text, source });
  const uploadedAt = new Date().toISOString();
  const digest = sha256(text);
  return {
    id: `DOC-${Date.now().toString(36)}-${digest.slice(0, 8)}`,
    name: String(name || 'Uploaded document'),
    source: String(source || 'upload'),
    path: String(filePath || name || ''),
    mime: String(mime || 'text/plain'),
    text,
    textLength: text.length,
    sha256: digest,
    tags: ['uploaded-document'],
    scan,
    uploadedAt
  };
}

function loadReadableDocuments() {
  return loadDocuments().filter((doc) => String(doc?.scan?.status || 'clean') !== 'quarantined');
}

function documentToEvidence(doc, score = 0, terms = []) {
  const snippet = buildSnippet(doc.text || '', terms.length ? terms : [String(doc.name || '').toLowerCase()], 240);
  return {
    id: doc.id,
    claim: doc.text || doc.name || 'Uploaded document',
    tags: Array.isArray(doc.tags) ? doc.tags : ['uploaded-document'],
    status: doc.scan?.status || 'clean',
    source: doc.source || 'upload',
    path: doc.path || doc.name || '',
    mime: doc.mime || 'text/plain',
    score,
    snippet,
    uploadedAt: doc.uploadedAt,
    scan: doc.scan || null
  };
}

function scoreDocuments(query, limit = 8) {
  const queryText = String(query || '').trim().toLowerCase();
  const terms = queryText.split(/\W+/).filter((term) => term.length > 1);
  const documents = loadReadableDocuments();
  if (!documents.length) {
    return [];
  }

  if (!terms.length) {
    return documents
      .slice()
      .sort((a, b) => String(b.uploadedAt || '').localeCompare(String(a.uploadedAt || '')))
      .slice(0, limit)
      .map((doc) => documentToEvidence(doc, 0, []));
  }

  const matches = documents
    .map((doc) => {
      const corpus = `${doc.name || ''} ${doc.source || ''} ${doc.path || ''} ${doc.text || ''}`.toLowerCase();
      let score = 0;
      for (const term of terms) {
        const regex = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
        const found = corpus.match(regex);
        if (found?.length) {
          score += found.length;
        }
      }
      if (!score) {
        return null;
      }
      return documentToEvidence(doc, score, terms);
    })
    .filter(Boolean)
    .sort((a, b) => (b.score || 0) - (a.score || 0) || String(b.uploadedAt || '').localeCompare(String(a.uploadedAt || '')));

  if (matches.length) {
    return matches.slice(0, limit);
  }

  return documents
    .slice()
    .sort((a, b) => String(b.uploadedAt || '').localeCompare(String(a.uploadedAt || '')))
    .slice(0, limit)
    .map((doc) => documentToEvidence(doc, 0, terms));
}

function searchKnowledge(query, limit = 8) {
  const uploaded = loadReadableDocuments();
  if (uploaded.length) {
    return scoreDocuments(query, limit);
  }
  return searchGraph(query, limit);
}

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
  const defaults = { theme: 'resolution_assurance_blue', provider: 'local', providerLabel: 'Local evidence fallback', fallbackProvider: 'local', retrievalBudgetMs: 1800, modelTimeoutMs: 8000, stream: true, localStorageRoot: DATA_ROOT, allowUnverifiedAnswer: true, blockFalseCompletion: true, fastMode: true };
  return { ...defaults, ...readJson(settingsFile, {}) };
}

function audit(event) {
  let prevHash = 'GENESIS';
  try { const lines = fs.readFileSync(auditFile, 'utf8').trim().split(/\r?\n/).filter(Boolean); if (lines.length) prevHash = JSON.parse(lines[lines.length - 1]).hash || prevHash; } catch {}
  const record = { ts: new Date().toISOString(), prevHash, ...event };
  record.hash = sha256(JSON.stringify(record));
  fs.appendFileSync(auditFile, JSON.stringify(record) + '\n');
  return record;
}

function searchGraph(query, limit = 8) {
  const q = String(query || '').toLowerCase().split(/\W+/).filter(Boolean);
  if (!q.length) return getGraph().slice(0, limit);
  return getGraph().map(n => { const hay = `${n.id} ${n.claim} ${(n.tags||[]).join(' ')}`.toLowerCase(); const score = q.reduce((a,t) => a + (hay.includes(t) ? 1 : 0), 0); return { ...n, score }; }).filter(n => n.score > 0).sort((a,b) => b.score - a.score).slice(0, limit);
}

function refine(question, draft, evidence) {
  const text = `${question} ${draft}`;
  const highImpact = /value|valuation|breach|legal|refund|compensation|robot|dose|cut|heat|lift|transport|completed|done|fixed|sealed|wired|located|tested/i.test(text);
  const completionClaim = /\b(done|completed|fixed|sealed|wired|located|tested|fully operational)\b/i.test(draft);
  let status = 'Not Verified'; let grade = 'F';
  if (evidence.length >= 3 && !completionClaim) { status = 'Verified'; grade = 'A'; }
  else if (evidence.length >= 1 && !completionClaim) { status = 'Partially Verified'; grade = 'C'; }
  if (completionClaim && !evidence.some(e => /completion|audit|proof/i.test((e.tags||[]).join(' ') + e.claim))) { status = 'Action Not Completed'; grade = 'F'; }
  if (highImpact && evidence.length < 2) { status = completionClaim ? 'Action Not Completed' : 'Not Verified'; grade = 'F'; }
  return { status, grade, evidenceIds: evidence.map(e => e.id), unverified: status !== 'Verified' };
}

function localAnswer(question, evidence, reason = '') {
  const evidenceText = evidence.map(e => `- ${e.id}: ${e.snippet || e.claim}`).join('\n') || '- No matching local evidence nodes.';
  return `${reason ? reason + '\n\n' : ''}I can answer from the local Resolution Assurance layer.\n\n${evidenceText}\n\nAnswer:\n${question}\n\nStatus note: this response is labelled by RA Refinery based on available local evidence.`;
}

async function claudeAnswer(question, evidence) {
  const key = process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY;
  if (!key) return null;
  const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), Number(getSettings().modelTimeoutMs || 8000));
  const evidenceText = evidence.map(e => `- ${e.id}: ${e.snippet || e.claim}`).join('\n') || 'No matching local evidence nodes.';
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', signal: controller.signal, headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model: process.env.RA_MODEL || 'claude-3-5-sonnet-latest', max_tokens: 900, system: 'You are Resolution AI. Answer like a normal helpful chatbot. Do not claim done/fixed/completed unless evidence proves it. If evidence is weak, answer but acknowledge uncertainty.', messages: [{ role: 'user', content: `Question:\n${question}\n\nLocal evidence:\n${evidenceText}` }] }) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return localAnswer(question, evidence, `Claude provider returned ${r.status}. Falling back locally.`);
    return (j.content || []).map(c => c.text || '').join('\n').trim() || localAnswer(question, evidence, 'Claude returned empty output. Falling back locally.');
  } catch (err) { return localAnswer(question, evidence, `Claude timed out or failed (${err.name || 'error'}). Falling back locally.`); }
  finally { clearTimeout(timeout); }
}
async function draftAnswer(question, evidence) {
  const settings = getSettings();
  if (settings.provider === 'anthropic') {
    return await claudeAnswer(question, evidence) || localAnswer(question, evidence, 'Claude was unavailable, so I fell back locally.');
  }
  return localAnswer(question, evidence);
}

app.get('/api/status', (req, res) => {
  const settings = getSettings();
  const provider = settings.provider === 'anthropic' && (process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY)
    ? 'Claude / Anthropic'
    : 'Local evidence fallback';
  res.json({ ok: true, app: 'Resolution AI / Sovereign Reality Engine', version: '0.3.1-blue-no-cache', port: PORT, provider, dataRoot: DATA_ROOT, documents: loadReadableDocuments().length, settings });
});
app.get('/api/settings', (req, res) => res.json(getSettings()));
app.post('/api/settings', (req, res) => { const next = { ...getSettings(), ...(req.body || {}) }; writeJson(settingsFile, next); const aud = audit({ type: 'settings_update', settingsHash: sha256(JSON.stringify(next)) }); res.json({ ok: true, settings: next, audit: aud.hash }); });
app.post('/api/chat', async (req, res) => { const question = safeText(req.body?.message || req.body?.question).trim(); if (!question) return res.status(400).json({ error: 'message required' }); const trace = [{ step: 'classify', status: 'ok' }]; const evidence = searchKnowledge(question, getSettings().maxGraphNodes || 8); trace.push({ step: 'knowledge', status: 'ok', count: evidence.length, mode: loadReadableDocuments().length ? 'uploaded-documents' : 'seed-graph' }); const draft = await draftAnswer(question, evidence); trace.push({ step: 'model', status: (process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY) ? 'claude_or_fallback' : 'local_fallback' }); const verification = refine(question, draft, evidence); trace.push({ step: 'ra_refinery', status: verification.status, grade: verification.grade }); const aud = audit({ type: 'chat', questionHash: sha256(question), verification, evidenceIds: verification.evidenceIds }); res.json({ answer: draft, verification, trace, audit: { id: aud.hash, prevHash: aud.prevHash }, evidence }); });
app.get('/api/graph/search', (req, res) => res.json({ results: searchKnowledge(String(req.query.q || ''), Number(req.query.limit || 20)) }));
app.post('/api/graph/anchor', (req, res) => { const graph = getGraph(); const node = { id: req.body?.id || `NODE-${Date.now()}`, claim: safeText(req.body?.claim), tags: req.body?.tags || [], status: 'rooted', createdAt: new Date().toISOString() }; graph.push(node); writeJson(graphFile, graph); const aud = audit({ type: 'graph_anchor', nodeId: node.id, claimHash: sha256(node.claim) }); res.json({ node, audit: aud.hash }); });
app.get('/api/audit', (req, res) => { try { res.type('text/plain').send(fs.readFileSync(auditFile, 'utf8')); } catch { res.type('text/plain').send(''); } });
app.get('/api/documents', (req, res) => {
  const docs = loadDocuments().map(({ text, ...doc }) => ({ ...doc, textLength: Number(doc.textLength || text?.length || 0) }));
  res.json({ ok: true, strictUploadOnly: Boolean(docs.length), count: docs.length, documents: docs });
});
app.get('/api/legal', (req, res) => res.json({ privacy: 'Local-first storage. Hosted provider use is optional and outputs are candidate material until verified.', terms: 'Prototype method documentation for Verified AI Operations. Human review required for high-impact decisions.', acceptableUse: 'Do not use for unlawful access, unsafe physical action, or unsupported completion claims.', verification: 'Every answer receives Verified, Partially Verified, Not Verified, Insufficient Evidence, Action Not Completed, or Refused for Safety.' }));
app.post('/api/upload', (req, res) => { const name = String(req.body?.name || `upload-${Date.now()}.txt`).replace(/[\\/:*?"<>|]/g, '_'); const mime = String(req.body?.mime || 'text/plain'); const content = cleanDocumentText(req.body?.content || ''); const scan = scanDocument({ name, mime, text: content, source: 'upload' }); if (!content.trim()) return res.status(400).json({ ok: false, error: 'upload content required' }); if (scan.status === 'quarantined') { const aud = audit({ type: 'upload_quarantined', file: name, mime, issues: scan.issues, sha256: sha256(content) }); appendJsonl(quarantineFile, { ts: new Date().toISOString(), file: name, mime, issues: scan.issues, audit: aud.hash }); return res.status(400).json({ ok: false, error: 'Upload quarantined by security scan.', scan, audit: aud.hash }); } const file = path.join(uploadsDir, name); fs.writeFileSync(file, content); const document = buildDocumentRecord({ name, source: 'upload', mime, content, path: file }); const documents = loadDocuments(); documents.unshift(document); saveDocuments(documents); appendJsonl(documentIndexFile, { ts: new Date().toISOString(), documentId: document.id, name: document.name, sha256: document.sha256, scan: document.scan.status, textLength: document.textLength }); const node = { id: document.id, claim: document.text, tags: document.tags, status: 'rooted', sha256: document.sha256, path: file, source: document.source, mime: document.mime, uploadedAt: document.uploadedAt }; const graph = getGraph(); graph.unshift(node); writeJson(graphFile, graph); const aud = audit({ type: 'upload', file: name, sha256: document.sha256, scan: document.scan.status }); res.json({ ok: true, file, document: { id: document.id, name: document.name, sha256: document.sha256, scan: document.scan, uploadedAt: document.uploadedAt, path: document.path, textLength: document.textLength }, audit: aud.hash }); });
app.get('/{*splat}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(PORT, () => console.log(`Resolution AI running at http://localhost:${PORT}`));

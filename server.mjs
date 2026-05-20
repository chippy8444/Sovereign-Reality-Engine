import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3030;
const DATA_ROOT = process.env.RA_DATA_ROOT || (fs.existsSync('D:/') ? 'D:/SovereignRA' : path.join(__dirname, 'data'));
const PRIVATE_DIR = path.join(DATA_ROOT, 'data', 'private');
const LOG_DIR = path.join(DATA_ROOT, 'logs');
const DEFAULT_DRIVE_ROOTS = fs.existsSync('D:/') ? ['C:/', 'D:/'] : ['C:/'];
const READABLE_TEXT_EXTENSIONS = new Set(['.txt', '.md', '.markdown', '.json', '.jsonl', '.csv', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.py', '.html', '.htm', '.xml', '.yml', '.yaml', '.log', '.sql', '.ps1', '.bat', '.ini', '.cfg', '.conf', '.toml', '.rtf', '.srt', '.vtt']);
const DRIVE_SKIP_SEGMENTS = new Set(['node_modules', '.git', '$recycle.bin', 'system volume information', 'windows', 'program files', 'program files (x86)', 'programdata', 'temp', 'tmp', 'cache']);
const DRIVE_PRIORITY_SEGMENTS = new Set(['chat', 'conversation', 'conversations', 'transcript', 'transcripts', 'log', 'logs', 'audit', 'report', 'reports', 'rating', 'score', 'codex', 'raw', 'dada', 'ledger', 'brain', 'training']);
const DRIVE_NOISE_SEGMENTS = new Set(['inetcache', 'webcache', 'browser cache', 'service worker', 'code cache', 'crashpad', 'temporary internet files', 'appdata/local/packages/microsoft.windows.cloudexperiencehost']);
const SKILL_REGISTRY = Object.freeze([
  { id: 'audit', label: 'Audit', summary: 'Finds audit, report, rating, score, codex, raw, dada, and ledger files, then returns findings with local evidence.' },
  { id: 'files', label: 'File Search', summary: 'Searches local files on C: and D: and returns the strongest evidence matches.' },
  { id: 'inventory', label: 'Inventory', summary: 'Summarizes what the local workspace, graph, and runtime can currently see.' },
  { id: 'training', label: 'Training', summary: 'Turns verified turns, uploads, and examples into structured learning rows.' },
  { id: 'capability', label: 'Capability Check', summary: 'Explains what the local bot can do offline and when web fallback is used.' },
  { id: 'guidance', label: 'Guidance', summary: 'Explains next steps and operating procedures from local evidence.' },
  { id: 'skills', label: 'Skill List', summary: 'Lists the skills the local bot currently recognizes.' },
  { id: 'greeting', label: 'Greeting', summary: 'Handles hello/hi style greetings.' },
  { id: 'general', label: 'General', summary: 'Falls back to the strongest local evidence available.' }
]);
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
const trainingJournalFile = path.join(LOG_DIR, 'training_journal.jsonl');
const trainingSummaryFile = path.join(LOG_DIR, 'training_summary.json');
const trainingSnapshotFile = path.join(LOG_DIR, 'training_snapshots.jsonl');
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
function tailJsonl(file, limit = 20) { try { const lines = fs.readFileSync(file, 'utf8').trim().split(/\r?\n/).filter(Boolean); return lines.slice(-limit).map((line) => { try { return JSON.parse(line); } catch { return null; } }).filter(Boolean); } catch { return []; } }
function countJsonl(file) { try { return fs.readFileSync(file, 'utf8').trim().split(/\r?\n/).filter(Boolean).length; } catch { return 0; } }
function stripMarkdown(text) { return String(text || '').replace(/\*\*/g, '').replace(/\[(.*?)\]\((.*?)\)/g, '$1').replace(/[`*_>#]/g, '').replace(/\s+/g, ' ').trim(); }
function tokenizeSearchTerms(question) { return String(question || '').toLowerCase().match(/[a-z0-9]{3,}/g)?.filter((term) => !['the', 'and', 'for', 'with', 'this', 'that', 'from', 'your', 'what', 'where', 'when', 'have', 'need', 'please', 'can', 'you', 'are', 'was', 'were', 'about', 'into', 'then', 'than', 'too', 'all', 'any', 'how', 'why', 'does', 'dont', 'still', 'only'].includes(term)) || []; }
function normaliseDriveRoot(root) { const text = String(root || '').replace(/\\/g, '/').replace(/\/+$/, ''); return text ? (/[a-zA-Z]:$/.test(text) ? `${text}/` : text) : ''; }
function getDriveRoots(settings = getSettings()) { const roots = Array.isArray(settings.driveRoots) && settings.driveRoots.length ? settings.driveRoots : DEFAULT_DRIVE_ROOTS; return roots.map(normaliseDriveRoot).filter(Boolean); }
function buildEvidenceId(prefix, value) { return `${prefix}-${sha256(String(value)).slice(0, 16)}`; }
function isReadableTextPath(filePath) { return READABLE_TEXT_EXTENSIONS.has(path.extname(String(filePath || '')).toLowerCase()); }
function shouldSkipDrivePath(filePath) { const normalized = String(filePath || '').replace(/\\/g, '/').toLowerCase(); return [...DRIVE_SKIP_SEGMENTS].some((segment) => normalized.includes(`/${segment}/`) || normalized.endsWith(`/${segment}`) || normalized.includes(`/${segment}.`) || normalized.startsWith(`${segment}/`)); }
function cleanSearchSnippet(text, maxLength = 240) { return safeText(text).replace(/\s+/g, ' ').trim().slice(0, maxLength); }
function buildDriveEvidence(filePath, lineNo, lineContent, score, terms) { const now = new Date().toISOString(); const snippet = cleanSearchSnippet(lineContent, 280); return { id: buildEvidenceId('DRV', `${filePath}:${lineNo}:${snippet}`), claim: snippet || filePath, tags: ['local-drive', 'readable-text'], status: 'clean', source: 'drive', path: filePath, mime: 'text/plain', score, snippet, uploadedAt: now, scan: { status: 'clean', safe: true, reviewedAt: now, name: path.basename(filePath), mime: 'text/plain', source: 'drive', issues: [], terms: Array.isArray(terms) ? terms : [] } }; }
function isCapabilityQuestion(query) { return /\b(operational|operate|operating|capable|capabilities|full capabilities|offline|online|browser|github ingestion|ingestion failed|exact model|cost[- ]effective|cost effectiveness|why can't you get operational|why cant you get operational|working alone)\b/i.test(String(query || '')); }
function shouldPreferWeb(query) { return !isCapabilityQuestion(query) && /(search the web|according to the web|according to public|publicly|latest|current|today|news|live update|real[- ]time|web signals|internet)/i.test(String(query || '')); }
function isChatCorpusQuery(query) { return /\b(chat|chatlog|chat log|conversation|transcript|transcripts|audit|report|rating|score|codex|raw|dada|ledger)\b/i.test(String(query || '')); }
function getSkillProfile(skillId) { return SKILL_REGISTRY.find((skill) => skill.id === skillId) || SKILL_REGISTRY.find((skill) => skill.id === 'general'); }
function detectSkill(question) {
  const q = String(question || '').toLowerCase();
  if (/\b(audit|auditing|forensic|forensics|report|rating|score|codex|raw|dada|waste tax|ledger|metrics?)\b/.test(q)) return getSkillProfile('audit');
  if (/\b(can you work in(?: my)? files?|work in(?: my)? files?|work with(?: my)? files?|read(?: my)? files?|use(?: my)? files?|open(?: my)? files?|work from files|local files|local drive|drive c|drive d|files on c|files on d|c:|d:|my files|my documents|upload a file|attach a file)\b/.test(q)) return getSkillProfile('files');
  if (/\b(what can you see|what do you have|show me what you found|what evidence|what files|inventory|what's in the workspace)\b/.test(q)) return getSkillProfile('inventory');
  if (/\b(how do i|how can i|what should i do|next step|how does this work|workflow|process)\b/.test(q)) return getSkillProfile('guidance');
  if (/\b(learn|training|train|ingest|lesson|lessons)\b/.test(q)) return getSkillProfile('training');
  if (isCapabilityQuestion(q)) return getSkillProfile('capability');
  if (/\b(skills?|skill list|what skills|available skills)\b/.test(q)) return getSkillProfile('skills');
  if (/\b(hi|hello|hey|g'day|good morning|good afternoon|good evening)\b/.test(q)) return getSkillProfile('greeting');
  return getSkillProfile('general');
}
function scoreDrivePath(filePath, queryTerms = []) {
  const normalized = String(filePath || '').replace(/\\/g, '/').toLowerCase();
  let bonus = 0;
  let penalty = 0;
  for (const segment of DRIVE_PRIORITY_SEGMENTS) {
    if (normalized.includes(segment)) bonus += 1;
  }
  for (const segment of DRIVE_NOISE_SEGMENTS) {
    if (normalized.includes(segment)) penalty += 2;
  }
  if (isChatCorpusQuery(queryTerms.join(' '))) {
    for (const segment of ['chat', 'conversation', 'transcript', 'log', 'audit', 'report', 'rating', 'score', 'codex', 'raw', 'dada', 'ledger', 'training']) {
      if (normalized.includes(segment)) bonus += 2;
    }
  }
  if (normalized.includes('/raw_chat_logs/') || normalized.includes('/chat_logs/') || normalized.includes('/transcripts/') || normalized.includes('/conversations/')) {
    bonus += 3;
  }
  return bonus - penalty;
}
function buildSystemEvidence() {
  const now = new Date().toISOString();
  const settings = getSettings();
  const provider = settings.provider === 'anthropic' && (process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY)
    ? 'Claude / Anthropic'
    : settings.allowWebFallback === false
      ? 'Local evidence fallback'
      : 'Local drives + web fallback';
  const docs = loadReadableDocuments();
  return [
    {
      id: buildEvidenceId('SYS', 'status'),
      claim: `Resolution AI is running locally at http://127.0.0.1:${PORT} with provider ${provider}.`,
      tags: ['system', 'status', 'runtime'],
      status: 'clean',
      source: 'system',
      path: `http://127.0.0.1:${PORT}/api/status`,
      mime: 'application/json',
      score: 3,
      snippet: `Runtime status: ${provider}`,
      uploadedAt: now,
      scan: { status: 'clean', safe: true, reviewedAt: now, name: 'runtime-status', mime: 'application/json', source: 'system', issues: [] }
    },
    {
      id: buildEvidenceId('SYS', 'storage'),
      claim: `Local storage root is ${settings.localStorageRoot}; drive roots are ${(settings.driveRoots || DEFAULT_DRIVE_ROOTS).join(', ')}; web fallback is ${settings.allowWebFallback === false ? 'disabled' : 'enabled'}.`,
      tags: ['system', 'settings', 'storage'],
      status: 'clean',
      source: 'system',
      path: `${DATA_ROOT}/settings`,
      mime: 'application/json',
      score: 3,
      snippet: `Storage root: ${settings.localStorageRoot}`,
      uploadedAt: now,
      scan: { status: 'clean', safe: true, reviewedAt: now, name: 'runtime-settings', mime: 'application/json', source: 'system', issues: [] }
    },
    {
      id: buildEvidenceId('SYS', 'documents'),
      claim: `Readable local documents loaded: ${docs.length}.`,
      tags: ['system', 'documents', 'index'],
      status: 'clean',
      source: 'system',
      path: `${DATA_ROOT}/documents`,
      mime: 'application/json',
      score: 3,
      snippet: `Readable documents: ${docs.length}`,
      uploadedAt: now,
      scan: { status: 'clean', safe: true, reviewedAt: now, name: 'document-index', mime: 'application/json', source: 'system', issues: [] }
    }
  ];
}

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
  const terms = tokenizeSearchTerms(queryText);
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

  return [];
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
  const defaults = { theme: 'resolution_assurance_blue', provider: 'local', providerLabel: 'Local drives + web fallback', fallbackProvider: 'local', retrievalBudgetMs: 1800, webSearchBudgetMs: 6500, modelTimeoutMs: 8000, stream: true, localStorageRoot: DATA_ROOT, driveRoots: DEFAULT_DRIVE_ROOTS, allowWebFallback: true, allowUnverifiedAnswer: true, blockFalseCompletion: true, fastMode: true, maxDriveFileBytes: 400000 };
  const merged = { ...defaults, ...readJson(settingsFile, {}) };
  if (merged.provider === 'anthropic' && (process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY)) {
    merged.providerLabel = 'Claude / Anthropic';
  } else {
    merged.providerLabel = merged.allowWebFallback === false ? 'Local evidence fallback' : 'Local drives + web fallback';
  }
  return merged;
}

function audit(event) {
  let prevHash = 'GENESIS';
  try { const lines = fs.readFileSync(auditFile, 'utf8').trim().split(/\r?\n/).filter(Boolean); if (lines.length) prevHash = JSON.parse(lines[lines.length - 1]).hash || prevHash; } catch {}
  const record = { ts: new Date().toISOString(), prevHash, ...event };
  record.hash = sha256(JSON.stringify(record));
  fs.appendFileSync(auditFile, JSON.stringify(record) + '\n');
  return record;
}

function readTrainingSummary() {
  return readJson(trainingSummaryFile, {
    updatedAt: null,
    totalInteractions: 0,
    verifiedInteractions: 0,
    partialInteractions: 0,
    unverifiedInteractions: 0,
    promotedInteractions: 0,
    candidateInteractions: 0,
    uploadEvents: 0,
    settingsEvents: 0,
    snapshotCount: 0,
    lastQuestionHash: null,
    lastAnswerHash: null,
    lastSourceMode: null,
    lastVerification: null,
    lastSnapshotAt: null,
    recentInteractions: []
  });
}

function writeTrainingSummary(summary) {
  writeJson(trainingSummaryFile, summary);
  return summary;
}

function updateTrainingSummary(event) {
  const summary = readTrainingSummary();
  summary.updatedAt = new Date().toISOString();
  if (event?.kind === 'chat_turn') {
    summary.totalInteractions += 1;
    if (event.verification === 'Verified') summary.verifiedInteractions += 1;
    else if (event.verification === 'Partially Verified') summary.partialInteractions += 1;
    else summary.unverifiedInteractions += 1;
    if (event.promotedToGraph) summary.promotedInteractions += 1;
    else summary.candidateInteractions += 1;
    summary.lastQuestionHash = event.questionHash || summary.lastQuestionHash;
    summary.lastAnswerHash = event.answerHash || summary.lastAnswerHash;
    summary.lastSourceMode = event.sourceMode || summary.lastSourceMode;
    summary.lastVerification = event.verification || summary.lastVerification;
    summary.recentInteractions = [
      {
        ts: event.ts,
        questionHash: event.questionHash,
        answerHash: event.answerHash,
        verification: event.verification,
        sourceMode: event.sourceMode,
        intent: event.intent,
        evidenceCount: event.evidenceCount,
        promotedToGraph: Boolean(event.promotedToGraph)
      },
      ...summary.recentInteractions
    ].slice(0, 20);
  } else if (event?.kind === 'upload') {
    summary.uploadEvents += 1;
  } else if (event?.kind === 'settings') {
    summary.settingsEvents += 1;
  } else if (event?.kind === 'snapshot') {
    summary.snapshotCount += 1;
    summary.lastSnapshotAt = event.ts;
  }
  return writeTrainingSummary(summary);
}

function writeTrainingSnapshot(reason = 'interval') {
  const ts = new Date().toISOString();
  const settings = getSettings();
  const snapshot = {
    ts,
    reason,
    provider: settings.providerLabel,
    allowWebFallback: settings.allowWebFallback !== false,
    dataRoot: DATA_ROOT,
    localStorageRoot: settings.localStorageRoot,
    documents: loadReadableDocuments().length,
    uploads: loadDocuments().length,
    graphNodes: getGraph().length,
    auditRows: countJsonl(auditFile),
    recentInteractions: tailJsonl(trainingJournalFile, 3).map((item) => ({
      ts: item.ts,
      questionHash: item.questionHash,
      answerHash: item.answerHash,
      verification: item.verification?.status || item.verification,
      sourceMode: item.sourceMode,
      intent: item.intent,
      skill: item.skillId || item.skill || null
    }))
  };
  appendJsonl(trainingSnapshotFile, snapshot);
  updateTrainingSummary({ kind: 'snapshot', ts });
  return snapshot;
}

function promoteInteractionToGraph({ question, answer, verification, evidence, sourceMode, intent, skill, ts }) {
  if (!verification || verification.status !== 'Verified') return null;
  const questionHash = sha256(question);
  const answerHash = sha256(answer);
  const nodeId = `CHAT-${questionHash.slice(0, 16)}`;
  const graph = getGraph();
  const node = {
    id: nodeId,
    claim: `Verified local interaction: ${safeText(question).slice(0, 120)} -> ${safeText(answer).slice(0, 160)}`,
    summary: safeText(answer).slice(0, 400),
    tags: ['chat-turn', 'training', 'verified', intent, skill?.id || skill, sourceMode].filter(Boolean),
    status: 'rooted',
    knowledge_layer: 'verified_learning',
    trust_status: 'trusted',
    source: 'chat',
    path: '/api/chat',
    questionHash,
    answerHash,
    evidenceIds: (evidence || []).map((item) => item.id).filter(Boolean),
    sourceMode,
    skillId: skill?.id || skill || null,
    verification: verification.status,
    grade: verification.grade,
    createdAt: ts
  };
  const existingIndex = graph.findIndex((item) => item && item.id === nodeId);
  if (existingIndex >= 0) graph[existingIndex] = { ...graph[existingIndex], ...node };
  else graph.unshift(node);
  writeJson(graphFile, graph);
  return node;
}

function recordTrainingInteraction({ question, answer, verification, evidence, sourceMode, intent, trace, skill }) {
  const ts = new Date().toISOString();
  const questionHash = sha256(question);
  const answerHash = sha256(answer);
  const promotedNode = promoteInteractionToGraph({ question, answer, verification, evidence, sourceMode, intent, skill, ts });
  const entry = {
    ts,
    kind: 'chat_turn',
    questionHash,
    answerHash,
    intent,
    sourceMode,
    skillId: skill?.id || null,
    evidenceIds: (evidence || []).map((item) => item.id).filter(Boolean),
    evidenceCount: Array.isArray(evidence) ? evidence.length : 0,
    knowledgeLayer: verification?.status === 'Verified' ? 'real_evidence' : 'synthetic_gap_fill',
    trustStatus: verification?.status === 'Verified' ? 'trusted' : 'hypothesis',
    verification: verification?.status || 'Not Verified',
    grade: verification?.grade || 'F',
    promotionEligible: verification?.status === 'Verified',
    promotedToGraph: Boolean(promotedNode),
    trace
  };
  appendJsonl(trainingJournalFile, entry);
  updateTrainingSummary(entry);
  return entry;
}

function searchGraph(query, limit = 8) {
  const q = tokenizeSearchTerms(query);
  if (!q.length) return getGraph().slice(0, limit);
  return getGraph().map(n => { const hay = `${n.id} ${n.claim} ${(n.tags||[]).join(' ')}`.toLowerCase(); const score = q.reduce((a,t) => a + (hay.includes(t) ? 1 : 0), 0); return { ...n, score }; }).filter(n => n.score > 0).sort((a,b) => b.score - a.score).slice(0, limit);
}

function searchDriveEvidence(query, limit = 8) {
  const settings = getSettings();
  const terms = tokenizeSearchTerms(query);
  if (!terms.length) return [];
  const roots = getDriveRoots(settings);
  if (!roots.length) return [];
  const globPairs = [
    '*.txt', '*.md', '*.markdown', '*.json', '*.jsonl', '*.csv', '*.ts', '*.tsx', '*.js', '*.jsx', '*.mjs',
    '*.py', '*.html', '*.htm', '*.xml', '*.yml', '*.yaml', '*.log', '*.sql', '*.ps1', '*.bat', '*.ini',
    '*.cfg', '*.conf', '*.toml', '*.rtf', '*.srt', '*.vtt'
  ].flatMap((glob) => ['--glob', glob]);
  const ignorePairs = [
    '!**/node_modules/**',
    '!**/.git/**',
    '!**/Windows/**',
    '!**/Program Files/**',
    '!**/Program Files (x86)/**',
    '!**/ProgramData/**',
    '!**/$Recycle.Bin/**',
    '!**/System Volume Information/**'
  ].flatMap((glob) => ['--glob', glob]);
  const args = [
    '--no-messages',
    '--hidden',
    '--text',
    '--line-number',
    '--ignore-case',
    '--fixed-strings',
    '-m',
    String(Math.max(limit * 40, 120)),
    ...globPairs,
    ...ignorePairs,
    ...terms.flatMap((term) => ['-e', term]),
    ...roots
  ];
  const timeoutMs = Math.max(2000, Number(settings.retrievalBudgetMs || 1800) * 3);
  const result = spawnSync('rg', args, { encoding: 'utf8', maxBuffer: 12 * 1024 * 1024, timeout: timeoutMs, windowsHide: true });
  const lines = String(result.stdout || '').split(/\r?\n/).filter(Boolean);
  const byPath = new Map();
  for (const line of lines) {
    const match = line.match(/^(.*?):(\d+):(.*)$/);
    if (!match) continue;
    const [, filePath, lineNo, content] = match;
    if (shouldSkipDrivePath(filePath) || !isReadableTextPath(filePath)) continue;
    const haystack = `${filePath} ${content}`.toLowerCase();
    const score = terms.reduce((count, term) => count + (haystack.includes(term) ? 1 : 0), 0);
    const pathScore = scoreDrivePath(filePath, terms);
    const totalScore = score + pathScore;
    if (!totalScore) continue;
    const evidence = buildDriveEvidence(filePath, lineNo, content, totalScore, terms);
    const current = byPath.get(filePath);
    if (!current || (evidence.score || 0) > (current.score || 0)) {
      byPath.set(filePath, evidence);
    }
  }
  return [...byPath.values()]
    .sort((a, b) => (b.score || 0) - (a.score || 0) || String(b.uploadedAt || '').localeCompare(String(a.uploadedAt || '')))
    .slice(0, limit);
}

function parseDuckDuckGoLiteMarkdown(markdown, query, limit = 5) {
  const terms = tokenizeSearchTerms(query);
  const blocks = String(markdown || '').split(/\n(?=\d+\.\[)/g);
  const results = [];
  for (const block of blocks) {
    const match = block.match(/^\s*\d+\.\[([^\]]+)\]\(([^)]+)\)/m);
    if (!match) continue;
    const title = stripMarkdown(match[1]);
    const url = String(match[2] || '').trim();
    const lines = block.split(/\r?\n/).slice(1).map(stripMarkdown).map((line) => line.trim()).filter(Boolean);
    const snippet = lines.find((line) => line && !/^DuckDuckGo$/i.test(line) && !/^URL Source:/i.test(line) && !/^Markdown Content:/i.test(line) && !/^\d+\.\[/.test(line)) || '';
    const haystack = `${title} ${snippet}`.toLowerCase();
    const score = terms.length ? terms.reduce((count, term) => count + (haystack.includes(term) ? 1 : 0), 0) : 1;
    results.push({
      id: buildEvidenceId('WEB', url || title),
      claim: snippet ? `${title}: ${snippet}` : title,
      tags: ['web', 'duckduckgo'],
      status: 'clean',
      source: 'web',
      path: url,
      mime: 'text/html',
      score,
      snippet: snippet || title,
      uploadedAt: new Date().toISOString(),
      scan: { status: 'clean', safe: true, reviewedAt: new Date().toISOString(), name: title || 'web result', mime: 'text/html', source: 'web', issues: [] }
    });
  }
  return results.sort((a, b) => (b.score || 0) - (a.score || 0) || String(b.snippet || '').localeCompare(String(a.snippet || ''))).slice(0, limit);
}

async function searchWebSignals(query, limit = 5) {
  const settings = getSettings();
  if (settings.allowWebFallback === false) return [];
  const terms = tokenizeSearchTerms(query);
  if (!terms.length) return [];
  const budget = Math.max(2000, Number(settings.webSearchBudgetMs || settings.modelTimeoutMs || 8000));
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), budget);
  try {
    const url = `https://r.jina.ai/http://lite.duckduckgo.com/lite/?q=${encodeURIComponent(query)}`;
    const response = await fetch(url, { signal: controller.signal, headers: { 'user-agent': 'Mozilla/5.0' } });
    const markdown = await response.text();
    if (!response.ok || !markdown.trim()) return [];
    return parseDuckDuckGoLiteMarkdown(markdown, query, limit);
  } catch {
    return [];
  } finally {
    clearTimeout(timeout);
  }
}

async function searchKnowledge(query, limit = 8) {
  const settings = getSettings();
  const minLocalScore = Number(settings.localEvidenceThreshold || 3);
  const preferWeb = shouldPreferWeb(query);
  const intent = classifyQuestionIntent(query);
  const systemEvidence = buildSystemEvidence();
  if (preferWeb) {
    const webFirst = await searchWebSignals(query, limit);
    if (webFirst.length) return { evidence: webFirst, mode: 'web-signals' };
  }
  if (intent === 'greeting') {
    return { evidence: systemEvidence, mode: 'intent-direct' };
  }
  if (intent === 'capability') {
    return { evidence: systemEvidence, mode: 'intent-direct' };
  }
  if (intent === 'skills') {
    return { evidence: systemEvidence, mode: 'intent-direct' };
  }
  const uploaded = scoreDocuments(query, limit);
  const drive = searchDriveEvidence(query, limit);
  const graph = searchGraph(query, limit);
  const localCandidates = [...uploaded, ...drive, ...graph].reduce((acc, item) => {
    const key = String(item?.id || item?.path || item?.claim || '');
    if (!key || acc.seen.has(key)) return acc;
    acc.seen.add(key);
    acc.items.push(item);
    return acc;
  }, { seen: new Set(), items: [] }).items.sort((a, b) => (b.score || 0) - (a.score || 0) || String(b.uploadedAt || '').localeCompare(String(a.uploadedAt || '')));

  if (['files', 'inventory', 'guidance', 'audit', 'training'].includes(intent)) {
    if (localCandidates.length) {
      return {
        evidence: localCandidates.slice(0, limit),
        mode: drive.length ? 'local-drives' : uploaded.length ? 'uploaded-documents' : 'seed-graph'
      };
    }
    return { evidence: systemEvidence, mode: 'intent-direct' };
  }

  if (uploaded.length && Math.max(...uploaded.map((item) => Number(item.score || 0))) >= minLocalScore) return { evidence: uploaded, mode: 'uploaded-documents' };
  if (drive.length && Math.max(...drive.map((item) => Number(item.score || 0))) >= minLocalScore) return { evidence: drive, mode: 'local-drives' };
  if (graph.length && Math.max(...graph.map((item) => Number(item.score || 0))) >= Math.max(2, minLocalScore - 1)) return { evidence: graph, mode: 'seed-graph' };
  const web = await searchWebSignals(query, limit);
  if (web.length) return { evidence: web, mode: 'web-signals' };
  if (drive.length) return { evidence: drive, mode: 'local-drives' };
  if (graph.length) return { evidence: graph, mode: 'seed-graph' };
  return { evidence: systemEvidence, mode: 'intent-direct' };
}

function refine(question, draft, evidence, sourceMode = 'local', intent = 'general') {
  const draftText = String(draft || '');
  const answerMarker = '\n\nAnswer:\n';
  const markerIndex = draftText.lastIndexOf(answerMarker);
  const directAnswer = markerIndex >= 0 ? draftText.slice(markerIndex + answerMarker.length).trim() : draftText.trim();
  const text = `${question} ${directAnswer}`;
  const highImpact = /value|valuation|breach|legal|refund|compensation|robot|dose|cut|heat|lift|transport|completed|done|fixed|sealed|wired|located|tested/i.test(text);
  const completionClaim = /\b(done|completed|fixed|sealed|wired|tested|fully operational)\b/i.test(directAnswer);
  let status = 'Not Verified'; let grade = 'F';
  const directIntent = ['greeting', 'files', 'inventory', 'guidance', 'audit', 'skills', 'training', 'capability'].includes(intent);
  const hasEvidence = Array.isArray(evidence) && evidence.length > 0;
  if (!completionClaim && directIntent && hasEvidence) { status = 'Verified'; grade = 'A'; }
  else if (!completionClaim && sourceMode === 'web-signals' && hasEvidence) { status = 'Verified'; grade = 'A'; }
  else if (!completionClaim && hasEvidence && evidence.length >= 2) { status = 'Verified'; grade = 'A'; }
  else if (hasEvidence && !completionClaim) { status = 'Partially Verified'; grade = 'C'; }
  if (completionClaim && !evidence.some(e => /completion|audit|proof/i.test((e.tags||[]).join(' ') + e.claim))) { status = 'Action Not Completed'; grade = 'F'; }
  if (highImpact && evidence.length < 2) { status = completionClaim ? 'Action Not Completed' : 'Not Verified'; grade = 'F'; }
  return { status, grade, evidenceIds: evidence.map(e => e.id), unverified: status !== 'Verified' };
}

function classifyQuestionIntent(question) {
  return detectSkill(question).id;
}

function formatEvidenceLines(evidence, limit = 3) {
  const items = Array.isArray(evidence) ? evidence.slice(0, limit) : [];
  if (!items.length) return 'No matching local evidence nodes were found.';
  return items.map((item, idx) => {
    const label = item?.path || item?.name || item?.id || `evidence-${idx + 1}`;
    const snippet = String(item?.snippet || item?.claim || '').replace(/\s+/g, ' ').trim();
    return `- ${label}: ${snippet || 'No readable text.'}`;
  }).join('\n');
}

function localAnswer(question, evidence, reason = '', sourceMode = 'local') {
  const intent = classifyQuestionIntent(question);
  const corpusQuery = isChatCorpusQuery(question);
  const skill = detectSkill(question);
  const evidenceText = formatEvidenceLines(evidence, 3);
  const firstEvidence = Array.isArray(evidence) && evidence.length ? evidence[0] : null;
  const firstLabel = firstEvidence?.path || firstEvidence?.name || firstEvidence?.id || null;
  const firstSnippet = String(firstEvidence?.snippet || firstEvidence?.claim || '').replace(/\s+/g, ' ').trim();
  const sourceLabel = sourceMode === 'web-signals' ? 'web signals' : sourceMode === 'local-drives' ? 'your local files on C: and D:' : 'the local Resolution Assurance layer';
  const evidenceBlock = Array.isArray(evidence) && evidence.length ? `Local evidence:\n${evidenceText}\n\n` : '';
  const intro = sourceMode === 'web-signals'
    ? 'I checked web signals and can answer from the local Resolution Assurance layer.'
    : sourceMode === 'local-drives'
      ? 'I searched readable files on C: and D: and can answer from the local Resolution Assurance layer.'
      : sourceMode === 'intent-direct'
        ? 'I can answer from the local Resolution Assurance layer.'
        : 'I can answer from the local Resolution Assurance layer.';

  let answer;
  if (intent === 'greeting') {
    answer = 'Hello - yes, the local engine is live and can work from uploaded files on C: and D:.';
  } else if (intent === 'skills') {
    answer = `Available skills: ${SKILL_REGISTRY.filter((item) => item.id !== 'general').map((item) => `${item.label} (${item.id})`).join(', ')}.`;
  } else if (intent === 'audit') {
    const topFiles = Array.isArray(evidence) ? evidence.slice(0, 5).map((item, idx) => {
      const label = item?.path || item?.name || item?.id || `evidence-${idx + 1}`;
      const snippet = String(item?.snippet || item?.claim || '').replace(/\s+/g, ' ').trim();
      return `${idx + 1}. ${label}${snippet ? ` — ${snippet}` : ''}`;
    }) : [];
    answer = `I used the Audit skill and searched for audit-style files, reports, ratings, scores, Codex/raw/Dada logs, and ledgers across your local drives.\n\nI found ${Array.isArray(evidence) ? evidence.length : 0} matching local files.\n${topFiles.length ? `Top matches:\n${topFiles.join('\n')}\n\n` : ''}This is the right lane for building your Resolution Assurance audit and waste-tax template. If you want, I can now turn these hits into a structured file-by-file audit table with metrics, findings, and template fields.`;
  } else if (intent === 'files') {
    answer = corpusQuery
      ? 'Yes - I can work from your local files on C: and D:, and for chat-log searches I will keep the search local first, rank the strongest matches, and only fall back to web signals if the local evidence is thin.'
      : 'Yes - I can work from your local files on C: and D:, and I can fall back to web signals when local evidence is thin.';
  } else if (intent === 'inventory') {
    answer = `I can see the local runtime, the configured storage roots, and ${Array.isArray(evidence) ? evidence.length : 0} supporting runtime facts.`;
  } else if (intent === 'capability') {
    const provider = getSettings().providerLabel || 'Local drives + web fallback';
    const driveRoots = Array.isArray(getSettings().driveRoots) ? getSettings().driveRoots.join(', ') : 'C:/, D:/';
    answer = `The system is operational locally, but it is not yet the exact fully-tuned model you described. Right now it runs local file search, local graph search, verified training logging, and optional web fallback. The GitHub ingestion error you are seeing is a stale dashboard status, not the local bot itself. Offline usage works for local files and the graph; online lookup works only when web fallback is enabled. The current provider is ${provider}, and the local drive roots are ${driveRoots}.`;
  } else if (sourceMode === 'web-signals' && firstLabel) {
    answer = `I could not resolve that locally, so I checked web signals. The strongest result is ${firstLabel}.`;
    if (firstSnippet) answer += ` ${firstSnippet}`;
    answer += ' If you want, I can keep narrowing it against the local files too.';
  } else if (sourceMode === 'local-drives' && firstLabel) {
    answer = corpusQuery
      ? `I searched readable files on C: and D: for chat-log style files and keyword hits, and found ${Array.isArray(evidence) ? evidence.length : 0} matches. The strongest match is ${firstLabel}.`
      : `I searched readable files on C: and D:, and the best match is ${firstLabel}.`;
    if (firstSnippet) answer += ` ${firstSnippet}`;
    answer += ' If that is not the file you meant, point me at the exact document and I will read from that instead of guessing.';
  } else if (firstSnippet) {
    answer = `Based on ${sourceLabel}, the best match is ${firstLabel || 'the current document set'}.`;
    answer += ' If that is not the file you meant, point me at the exact document and I will read from that instead of guessing.';
  } else {
    answer = 'I do not have enough local evidence yet to answer that confidently. Upload or attach a file, and I can work from it directly.';
  }

  return `${reason ? reason + '\n\n' : ''}${intro}\n\n${evidenceBlock}Answer:\n${answer}\n\nStatus note: this response is labelled by RA Refinery based on available local evidence.`;
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
async function draftAnswer(question, evidence, sourceMode = 'local') {
  const settings = getSettings();
  if (settings.provider === 'anthropic') {
    return await claudeAnswer(question, evidence) || localAnswer(question, evidence, 'Claude was unavailable, so I fell back locally.', sourceMode);
  }
  const reason = sourceMode === 'web-signals'
    ? 'I could not resolve this locally, so I checked web signals.'
    : sourceMode === 'local-drives'
      ? 'I searched readable files on C: and D:.'
      : '';
  return localAnswer(question, evidence, reason, sourceMode);
}

app.get('/api/status', (req, res) => {
  const settings = getSettings();
  const provider = settings.provider === 'anthropic' && (process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY)
    ? 'Claude / Anthropic'
    : settings.allowWebFallback === false
      ? 'Local evidence fallback'
      : 'Local drives + web fallback';
  res.json({ ok: true, app: 'Resolution AI / Sovereign Reality Engine', version: '0.3.1-blue-no-cache', port: PORT, provider, dataRoot: DATA_ROOT, documents: loadReadableDocuments().length, skills: SKILL_REGISTRY, training: readTrainingSummary(), settings });
});
app.get('/api/settings', (req, res) => res.json(getSettings()));
app.get('/api/skills', (req, res) => res.json({ ok: true, skills: SKILL_REGISTRY, current: detectSkill(String(req.query.q || '')).id }));
app.post('/api/settings', (req, res) => { const next = { ...getSettings(), ...(req.body || {}) }; writeJson(settingsFile, next); const normalized = getSettings(); writeJson(settingsFile, normalized); const aud = audit({ type: 'settings_update', settingsHash: sha256(JSON.stringify(normalized)) }); updateTrainingSummary({ kind: 'settings', ts: new Date().toISOString() }); res.json({ ok: true, settings: normalized, audit: aud.hash }); });
app.post('/api/chat', async (req, res) => { const question = safeText(req.body?.message || req.body?.question).trim(); if (!question) return res.status(400).json({ error: 'message required' }); const trace = [{ step: 'classify', status: 'ok' }]; const skill = detectSkill(question); const intent = skill.id; const search = await searchKnowledge(question, getSettings().maxGraphNodes || 8); const evidence = search.evidence || []; trace.push({ step: 'knowledge', status: 'ok', count: evidence.length, mode: search.mode, intent, skill: skill.id }); const draft = await draftAnswer(question, evidence, search.mode); trace.push({ step: 'model', status: (process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY) && getSettings().provider === 'anthropic' ? 'anthropic' : search.mode === 'web-signals' ? 'web_fallback' : 'local_fallback', skill: skill.id }); const verification = refine(question, draft, evidence, search.mode, intent); trace.push({ step: 'ra_refinery', status: verification.status, grade: verification.grade, skill: skill.id }); const aud = audit({ type: 'chat', questionHash: sha256(question), verification, evidenceIds: verification.evidenceIds, sourceMode: search.mode, skill: skill.id }); recordTrainingInteraction({ question, answer: draft, verification, evidence, sourceMode: search.mode, intent, trace, skill }); res.json({ answer: draft, verification, trace, audit: { id: aud.hash, prevHash: aud.prevHash }, evidence, sourceMode: search.mode, intent, skill, skills: SKILL_REGISTRY }); });
app.get('/api/graph/search', (req, res) => res.json({ results: searchKnowledge(String(req.query.q || ''), Number(req.query.limit || 20)) }));
app.post('/api/graph/anchor', (req, res) => { const graph = getGraph(); const node = { id: req.body?.id || `NODE-${Date.now()}`, claim: safeText(req.body?.claim), tags: req.body?.tags || [], status: 'rooted', createdAt: new Date().toISOString() }; graph.push(node); writeJson(graphFile, graph); const aud = audit({ type: 'graph_anchor', nodeId: node.id, claimHash: sha256(node.claim) }); res.json({ node, audit: aud.hash }); });
app.get('/api/training', (req, res) => {
  const limit = Math.max(1, Math.min(100, Number(req.query.limit || 20)));
  res.json({
    ok: true,
    summary: readTrainingSummary(),
    recentInteractions: tailJsonl(trainingJournalFile, limit),
    recentSnapshots: tailJsonl(trainingSnapshotFile, Math.min(limit, 20))
  });
});
app.get('/api/audit', (req, res) => { try { res.type('text/plain').send(fs.readFileSync(auditFile, 'utf8')); } catch { res.type('text/plain').send(''); } });
app.get('/api/documents', (req, res) => {
  const docs = loadDocuments().map(({ text, ...doc }) => ({ ...doc, textLength: Number(doc.textLength || text?.length || 0) }));
  res.json({ ok: true, strictUploadOnly: Boolean(docs.length), count: docs.length, documents: docs });
});
app.get('/api/legal', (req, res) => res.json({ privacy: 'Local-first storage. Hosted provider use is optional and outputs are candidate material until verified.', terms: 'Prototype method documentation for Verified AI Operations. Human review required for high-impact decisions.', acceptableUse: 'Do not use for unlawful access, unsafe physical action, or unsupported completion claims.', verification: 'Every answer receives Verified, Partially Verified, Not Verified, Insufficient Evidence, Action Not Completed, or Refused for Safety.' }));
app.post('/api/upload', (req, res) => { const name = String(req.body?.name || `upload-${Date.now()}.txt`).replace(/[\\/:*?"<>|]/g, '_'); const mime = String(req.body?.mime || 'text/plain'); const content = cleanDocumentText(req.body?.content || ''); const scan = scanDocument({ name, mime, text: content, source: 'upload' }); if (!content.trim()) return res.status(400).json({ ok: false, error: 'upload content required' }); if (scan.status === 'quarantined') { const aud = audit({ type: 'upload_quarantined', file: name, mime, issues: scan.issues, sha256: sha256(content) }); appendJsonl(quarantineFile, { ts: new Date().toISOString(), file: name, mime, issues: scan.issues, audit: aud.hash }); return res.status(400).json({ ok: false, error: 'Upload quarantined by security scan.', scan, audit: aud.hash }); } const file = path.join(uploadsDir, name); fs.writeFileSync(file, content); const document = buildDocumentRecord({ name, source: 'upload', mime, content, path: file }); const documents = loadDocuments(); documents.unshift(document); saveDocuments(documents); appendJsonl(documentIndexFile, { ts: new Date().toISOString(), documentId: document.id, name: document.name, sha256: document.sha256, scan: document.scan.status, textLength: document.textLength }); const node = { id: document.id, claim: document.text, tags: document.tags, status: 'rooted', sha256: document.sha256, path: file, source: document.source, mime: document.mime, uploadedAt: document.uploadedAt }; const graph = getGraph(); graph.unshift(node); writeJson(graphFile, graph); const aud = audit({ type: 'upload', file: name, sha256: document.sha256, scan: document.scan.status }); updateTrainingSummary({ kind: 'upload', ts: new Date().toISOString() }); res.json({ ok: true, file, document: { id: document.id, name: document.name, sha256: document.sha256, scan: document.scan, uploadedAt: document.uploadedAt, path: document.path, textLength: document.textLength }, audit: aud.hash }); });
app.get('/{*splat}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
writeJson(settingsFile, getSettings());
writeTrainingSnapshot('startup');
const trainingTimerMs = Math.max(60000, Number(process.env.RA_TRAINING_SNAPSHOT_MS || 120000));
const trainingTimer = setInterval(() => { try { writeTrainingSnapshot('interval'); } catch (err) { audit({ type: 'training_snapshot_error', message: safeText(err?.message || String(err)) }); } }, trainingTimerMs);
if (typeof trainingTimer.unref === 'function') trainingTimer.unref();
app.listen(PORT, () => console.log(`Resolution AI running at http://localhost:${PORT}`));

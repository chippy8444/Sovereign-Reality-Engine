import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const DATA_ROOT = process.env.RA_DATA_ROOT || path.join(ROOT, 'data');
const PRIVATE_DIR = path.join(DATA_ROOT, 'data', 'private');
const LOG_DIR = path.join(DATA_ROOT, 'logs');
const OUT_DIR = path.join(ROOT, 'data', 'ra-edge-exports');
const GRAPH_FILE = path.join(PRIVATE_DIR, 'graph.json');
const AUDIT_FILE = path.join(LOG_DIR, 'sovereign_audit.jsonl');

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function sha256Json(value) {
  return sha256(JSON.stringify(value, Object.keys(value).sort()));
}

function utcNow() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function readAuditTail(file) {
  try {
    const lines = fs.readFileSync(file, 'utf8').trim().split(/\r?\n/).filter(Boolean);
    if (!lines.length) return { audit_rows: 0, last_audit_hash: null, last_audit_time_utc: null };
    const last = JSON.parse(lines[lines.length - 1]);
    return {
      audit_rows: lines.length,
      last_audit_hash: last.hash || null,
      last_audit_prev_hash: last.prevHash || null,
      last_audit_time_utc: last.ts || null,
    };
  } catch {
    return { audit_rows: 0, last_audit_hash: null, last_audit_time_utc: null };
  }
}

function defaultGraph() {
  return [
    { id: 'NODE-RA-001', claim: 'Verified AI Operations routes AI output through verification before operational trust.', tags: ['verified-ai-operations', 'method', 'ra'], status: 'rooted' },
    { id: 'NODE-RA-002', claim: 'Completion language must be blocked unless completion proof exists.', tags: ['completion-proof', 'false-completion'], status: 'rooted' },
    { id: 'NODE-RA-003', claim: 'User-owned local storage is the default privacy posture.', tags: ['privacy', 'local-storage', 'D-drive'], status: 'rooted' },
    { id: 'NODE-RA-004', claim: 'Unverified answers should still be returned with a clear Not Verified badge when safe.', tags: ['verification', 'ux'], status: 'rooted' },
    { id: 'NODE-RA-005', claim: 'Hosted models are candidate generators, not final truth authorities.', tags: ['hosted-ai', 'ra-refinery'], status: 'rooted' },
    { id: 'NODE-RA-006', claim: 'Robots require task state, authority, sensor evidence, safety envelope, abort path, completion proof, and audit record before physical action.', tags: ['robotics', 'safety', 'baseline'], status: 'rooted' },
  ];
}

function publicNodePacket(node, auditTail, index) {
  const claim = String(node.claim || node.id || 'SRE graph node');
  const tags = Array.isArray(node.tags) ? node.tags.map(String).slice(0, 20) : [];
  const subject = `${node.id || `sre-node-${index}`}: ${claim.slice(0, 120)}`;
  const packet = {
    schema_version: 'ra.edge.v1',
    source_node: 'sovereign-reality-engine',
    target_graph: 'resolution-assurance-protocol/data/graph',
    event_time_utc: utcNow(),
    edge_type: 'supports',
    subject,
    subject_hash: sha256(subject),
    claim_hash: sha256(claim),
    evidence_hash: sha256(JSON.stringify({ id: node.id || null, tags, status: node.status || null })),
    local_node_id_hash: sha256(String(node.id || `sre-node-${index}`)),
    local_status: String(node.status || 'unknown'),
    tag_hashes: tags.map((tag) => sha256(tag)),
    audit_prev_hash: auditTail.last_audit_prev_hash || null,
    audit_hash: auditTail.last_audit_hash || null,
    source_audit_rows: auditTail.audit_rows || 0,
    privacy: 'metadata_only',
    raw_private_data_moved: false,
  };
  packet.packet_hash_sha256 = sha256Json(packet);
  return packet;
}

function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const graph = readJson(GRAPH_FILE, defaultGraph());
  const nodes = Array.isArray(graph) ? graph : defaultGraph();
  const auditTail = readAuditTail(AUDIT_FILE);
  const packets = nodes.slice(0, 500).map((node, index) => publicNodePacket(node, auditTail, index));
  const generated = utcNow();
  const summary = {
    schema_version: 'ra.edge_export_summary.v1',
    generated_time_utc: generated,
    source_node: 'sovereign-reality-engine',
    target_graph: 'resolution-assurance-protocol/data/graph',
    packet_count: packets.length,
    audit_rows: auditTail.audit_rows || 0,
    last_audit_hash: auditTail.last_audit_hash || null,
    privacy: 'metadata_only',
    raw_private_data_moved: false,
    export_hash_sha256: sha256(packets.map((packet) => packet.packet_hash_sha256).join('\n')),
  };
  fs.writeFileSync(path.join(OUT_DIR, 'sre-edge-packets.jsonl'), packets.map((packet) => JSON.stringify(packet)).join('\n') + '\n');
  fs.writeFileSync(path.join(OUT_DIR, 'sre-edge-export-summary.json'), JSON.stringify(summary, null, 2) + '\n');
  console.log(JSON.stringify(summary, null, 2));
}

main();

'use strict';
/**
 * Proof Gatekeeper agent for the zkVerify Agent Games.
 *
 * Protocol (from https://agentgames.zkverify.io/build and /rules, read 2026-11-16):
 *  - Platform POSTs a signed JSON envelope to this endpoint.
 *  - Inbound signature: header `x-agent-games-signature` = HMAC over the RAW body,
 *    verified BEFORE parsing. (Algorithm/encoding are not named on the page; we use
 *    HMAC-SHA256 hex — see README "Assumptions".)
 *  - Preflight: { type: "agent-games.preflight.v1", ... } ->
 *               { ok: true, protocolVersion: "v1" } (signed).
 *  - Task:      { type: "agent-games.proof-gatekeeper.v1", task_id, mode,
 *                 issued_at, deadline_at, input: { registered_vk, proof_vk, minimum,
 *                 public_balance, expiry_block, current_block, recipient,
 *                 condition_recipient, amount, max_transfer, proof_tx } }
 *               -> { decision: "APPROVE"|"REJECT", reason_code, proof,
 *                    public_signals, proof_tx } (signed).
 *  - Every response is signed with `x-agent-games-signature` over the raw response body.
 *  - 60s hard deadline, fail closed: any error/uncertainty -> REJECT.
 *  - task_id is an idempotency key: retries get the identical response bytes.
 *
 * The Groth16 circuit is the referee: decision=1 iff every in-circuit check passes.
 * A proof is attached only when its public `decision` signal equals the decision
 * in the response body.
 */
const http = require('http');
const crypto = require('crypto');
const path = require('path');
const snarkjs = require('snarkjs');

// ---------------------------------------------------------------- config
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || process.env.AGENT_HMAC_SECRET || '';
if (!SECRET) {
  console.error('FATAL: set AGENT_GAMES_HMAC_SECRET (or AGENT_HMAC_SECRET) in the environment.');
  process.exit(1);
}
const PORT = parseInt(process.env.PORT || '8787', 10);
const HOST = process.env.HOST || '0.0.0.0';
// Official registered gatekeeper vk hash, from GET /api/circuit-info (2026-11-16).
const REGISTERED_VK_HASH = process.env.REGISTERED_VK_HASH ||
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const WASM = path.join(__dirname, 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');

// BN128 (BN254) scalar field prime — circuit inputs are field elements.
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const modP = (x) => ((x % P) + P) % P;

// ---------------------------------------------------------------- helpers
const log = (...a) => console.log(new Date().toISOString(), ...a);

function hmacHex(rawBody) {
  return crypto.createHmac('sha256', SECRET).update(rawBody).digest('hex');
}
function signatureValid(rawBody, header) {
  if (!header || typeof header !== 'string') return false;
  const provided = header.startsWith('sha256=') ? header.slice(7) : header;
  const expected = hmacHex(rawBody);
  const a = Buffer.from(provided.toLowerCase(), 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function sendSigned(res, status, objOrRaw) {
  const raw = typeof objOrRaw === 'string' ? objOrRaw : JSON.stringify(objOrRaw);
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-agent-games-signature': hmacHex(raw),
  });
  res.end(raw);
}
// Parse a decimal string / number / 0x-hex string into a BigInt, or null.
function toBigInt(v) {
  try {
    if (typeof v === 'number') return Number.isSafeInteger(v) ? BigInt(v) : null;
    if (typeof v === 'bigint') return v;
    if (typeof v === 'string') {
      const s = v.trim();
      if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
      if (/^-?\d+$/.test(s)) return BigInt(s);
    }
  } catch (_) { /* fall through */ }
  return null;
}
// Circuit `taskId` is a field element. Envelope task_ids look like "gk_24_9d1";
// the verified participant write-up used taskId=24 for such an id (Poseidon check
// reproduced locally). Fallbacks documented in README.
function taskIdToField(taskId) {
  if (typeof taskId === 'number') return BigInt(taskId);
  const s = String(taskId || '');
  const m = s.match(/^gk_(\d+)(?:_|$)/) || s.match(/(\d+)/);
  if (m) return BigInt(m[1]);
  // FNV-1a 32-bit over the raw string (last-resort deterministic mapping)
  let h = 2166136261n;
  for (const ch of Buffer.from(s, 'utf8')) {
    h ^= BigInt(ch);
    h = (h * 16777619n) & 0xffffffffn;
  }
  return h;
}
function randomSalt() {
  return BigInt('0x' + crypto.randomBytes(31).toString('hex'));
}

// Serialize proof generation (wasm witness calc is CPU/memory heavy; tasks are
// low-volume — 8/day — so a simple queue is safest on small hosts).
let proveQueue = Promise.resolve();
function prove(input) {
  const run = () => snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const p = proveQueue.then(run, run);
  proveQueue = p.catch(() => {});
  return p;
}

// ---------------------------------------------------------------- state
const seenProofTx = new Map(); // proof_tx -> task_id (replay protection)
const taskCache = new Map();   // task_id -> { bodyHash, rawResponse }

// ---------------------------------------------------------------- decision
const REASONS = {
  APPROVE: 'ALL_CHECKS_PASSED',
  VK_NOT_REGISTERED: 'VK_NOT_REGISTERED',
  PROOF_REUSED: 'PROOF_REUSED',
  VK_SUBSTITUTION: 'VK_SUBSTITUTION',
  THRESHOLD_MISMATCH: 'THRESHOLD_MISMATCH',
  CONDITION_EXPIRED: 'CONDITION_EXPIRED',
  RECIPIENT_MISMATCH: 'RECIPIENT_MISMATCH',
  AMOUNT_OVERFLOW: 'AMOUNT_OVERFLOW',
  MALFORMED_INPUT: 'MALFORMED_INPUT',
  PROOF_GENERATION_FAILED: 'PROOF_GENERATION_FAILED',
  TASK_ID_CONFLICT: 'TASK_ID_CONFLICT',
};

async function handleGatekeeperTask(env) {
  const started = Date.now();
  const taskIdRaw = env.task_id;
  const input = env.input || {};

  const f = {
    registeredVkHash: toBigInt(input.registered_vk),
    proofVkHash: toBigInt(input.proof_vk),
    minimum: toBigInt(input.minimum),
    publicBalance: toBigInt(input.public_balance),
    expiryBlock: toBigInt(input.expiry_block),
    currentBlock: toBigInt(input.current_block),
    recipient: toBigInt(input.recipient),
    conditionRecipient: toBigInt(input.condition_recipient),
    amount: toBigInt(input.amount),
    maxTransfer: toBigInt(input.max_transfer),
  };
  const proofTx = typeof input.proof_tx === 'string' && input.proof_tx ? input.proof_tx : null;

  const bareReject = (reason) => {
    const body = { decision: 'REJECT', reason_code: reason };
    if (proofTx) body.proof_tx = proofTx;
    log('task', taskIdRaw, '-> REJECT', reason, '(no proof)', `${Date.now() - started}ms`);
    return body;
  };

  if (Object.values(f).some((v) => v === null)) {
    return bareReject(REASONS.MALFORMED_INPUT);
  }

  // --- off-circuit checks (the circuit cannot see these; guide §04) ---
  let offCircuitReason = null;
  if (modP(f.registeredVkHash) !== modP(BigInt(REGISTERED_VK_HASH))) {
    offCircuitReason = REASONS.VK_NOT_REGISTERED;
  } else if (proofTx && seenProofTx.has(proofTx) && seenProofTx.get(proofTx) !== taskIdRaw) {
    offCircuitReason = REASONS.PROOF_REUSED;
  }

  // --- in-circuit checks, mirrored in JS (circuit is the final referee) ---
  const checks = [
    [modP(f.proofVkHash) === modP(f.registeredVkHash), REASONS.VK_SUBSTITUTION],
    [f.publicBalance >= f.minimum, REASONS.THRESHOLD_MISMATCH],
    [f.currentBlock <= f.expiryBlock, REASONS.CONDITION_EXPIRED],
    [modP(f.recipient) === modP(f.conditionRecipient), REASONS.RECIPIENT_MISMATCH],
    [f.amount <= f.maxTransfer, REASONS.AMOUNT_OVERFLOW],
  ];
  const failedCheck = checks.find(([ok]) => !ok);
  const circuitVerdict = failedCheck ? 0 : 1;
  const circuitReason = failedCheck ? failedCheck[1] : REASONS.APPROVE;

  let decision = offCircuitReason ? 0 : circuitVerdict;
  let reason = offCircuitReason || circuitReason;

  const circuitInput = {
    registeredVkHash: f.registeredVkHash.toString(),
    proofVkHash: f.proofVkHash.toString(),
    minimum: f.minimum.toString(),
    publicBalance: f.publicBalance.toString(),
    expiryBlock: f.expiryBlock.toString(),
    currentBlock: f.currentBlock.toString(),
    recipient: f.recipient.toString(),
    conditionRecipient: f.conditionRecipient.toString(),
    amount: f.amount.toString(),
    maxTransfer: f.maxTransfer.toString(),
    decision: String(decision),
    taskId: taskIdToField(taskIdRaw).toString(),
    salt: randomSalt().toString(),
  };

  // --- prove; the circuit has the final word on the in-circuit verdict ---
  let proved = null;
  try {
    proved = await prove(circuitInput);
  } catch (e) {
    log('task', taskIdRaw, 'prove(decision=' + decision + ') failed:', String(e).slice(0, 140));
    if (!offCircuitReason) {
      // Our JS mirror disagreed with the circuit — trust the circuit.
      const flipped = decision === 1 ? 0 : 1;
      try {
        proved = await prove({ ...circuitInput, decision: String(flipped) });
        decision = flipped;
        reason = flipped === 1 ? REASONS.APPROVE : circuitReason;
        log('task', taskIdRaw, 'circuit overruled JS verdict -> decision', flipped);
      } catch (e2) {
        log('task', taskIdRaw, 'prove(flipped) also failed:', String(e2).slice(0, 140));
      }
    }
  }

  if (proofTx && !seenProofTx.has(proofTx)) seenProofTx.set(proofTx, taskIdRaw);

  if (!proved) {
    // Fail closed. If we intended APPROVE but cannot prove it, we still reject:
    // an unprovable approval must never leave this endpoint (guide: fail closed).
    return bareReject(decision === 1 ? REASONS.PROOF_GENERATION_FAILED : reason);
  }

  // Attach the proof only if its decision signal matches the response decision.
  const proofDecision = proved.publicSignals[11];
  if (proofDecision !== String(decision)) {
    log('task', taskIdRaw, 'proof decision signal mismatch — dropping proof');
    return bareReject(REASONS.PROOF_GENERATION_FAILED);
  }

  const body = {
    decision: decision === 1 ? 'APPROVE' : 'REJECT',
    reason_code: reason,
    proof: proved.proof,
    public_signals: proved.publicSignals,
  };
  if (proofTx) body.proof_tx = proofTx;
  log('task', taskIdRaw, '->', body.decision, reason, '(proof attached)', `${Date.now() - started}ms`);
  return body;
}

// ---------------------------------------------------------------- server
const server = http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/health' || req.url === '/')) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'proof-gatekeeper', protocolVersion: 'v1' }));
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: false, error: 'method not allowed' }));
    return;
  }
  const chunks = [];
  let size = 0;
  req.on('data', (c) => {
    size += c.length;
    if (size > 1024 * 1024) req.destroy();
    else chunks.push(c);
  });
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    // 1. Verify HMAC over the raw body BEFORE parsing (guide §02).
    if (!signatureValid(raw, req.headers['x-agent-games-signature'])) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'invalid signature' }));
      return;
    }
    let env;
    try {
      env = JSON.parse(raw.toString('utf8'));
    } catch (_) {
      sendSigned(res, 400, { ok: false, error: 'invalid json' });
      return;
    }
    try {
      if (env.type === 'agent-games.preflight.v1') {
        sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
        log('preflight ok');
        return;
      }
      if (env.type === 'agent-games.proof-gatekeeper.v1') {
        const taskId = String(env.task_id || '');
        const bodyHash = crypto.createHash('sha256').update(raw).digest('hex');
        const cached = taskCache.get(taskId);
        if (cached) {
          if (cached.bodyHash === bodyHash) {
            sendSigned(res, 200, cached.rawResponse); // idempotent retry
            log('task', taskId, 'idempotent replay');
          } else {
            sendSigned(res, 200, { decision: 'REJECT', reason_code: REASONS.TASK_ID_CONFLICT });
            log('task', taskId, 'task_id reused with different body -> REJECT');
          }
          return;
        }
        const body = await handleGatekeeperTask(env);
        const rawResponse = JSON.stringify(body);
        taskCache.set(taskId, { bodyHash, rawResponse });
        sendSigned(res, 200, rawResponse);
        return;
      }
      sendSigned(res, 400, { ok: false, error: 'unsupported type' });
    } catch (e) {
      log('handler error:', String(e).slice(0, 200));
      // Fail closed on any unexpected error.
      try { sendSigned(res, 200, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' }); } catch (_) {}
    }
  });
});

server.listen(PORT, HOST, () => log(`proof-gatekeeper listening on ${HOST}:${PORT}`));

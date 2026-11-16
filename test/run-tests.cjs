'use strict';
/** End-to-end local test: spawn the agent with a dev secret, POST signed sample
 *  envelopes, and verify returned proofs with the snarkjs CLI. */
const { spawn, execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PORT = 18787;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'dev-secret-for-local-tests-only';
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR = '0xDe42aBcDeF0123456789AbCdEf0123456789aB9f01'.slice(0, 42); // 20-byte addr
const ADDR2 = '0x1111111111111111111111111111111111111111';

const sign = (raw) => crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
const results = [];
function check(name, cond, extra = '') {
  results.push([name, !!cond, extra]);
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);
}
async function post(obj, { badSig = false } = {}) {
  const raw = JSON.stringify(obj);
  const res = await fetch(`${BASE}/agent`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-agent-games-signature': badSig ? 'deadbeef' : sign(raw),
    },
    body: raw,
  });
  const text = await res.text();
  return { status: res.status, sig: res.headers.get('x-agent-games-signature'), body: JSON.parse(text), rawText: text };
}
function envelope(taskId, overrides = {}, inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xtx_' + taskId,
      ...inputOverrides,
    },
    ...overrides,
  };
}
function cliVerify(tag, body) {
  const dir = path.join(__dirname, tag);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'proof.json'), JSON.stringify(body.proof, null, 2));
  fs.writeFileSync(path.join(dir, 'public.json'), JSON.stringify(body.public_signals, null, 2));
  const out = execFileSync('node', [
    path.join(ROOT, 'node_modules', 'snarkjs', 'build', 'cli.cjs'),
    'groth16', 'verify',
    path.join(ROOT, 'circuits', 'verification_key.json'),
    path.join(dir, 'public.json'),
    path.join(dir, 'proof.json'),
  ], { encoding: 'utf8' });
  return out;
}

(async () => {
  const server = spawn('node', [path.join(ROOT, 'agent.cjs')], {
    env: { ...process.env, AGENT_GAMES_HMAC_SECRET: SECRET, PORT: String(PORT) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (d) => process.stdout.write('[server] ' + d));
  server.stderr.on('data', (d) => process.stdout.write('[server:err] ' + d));
  try {
    // wait for health
    let up = false;
    for (let i = 0; i < 50 && !up; i++) {
      try { const r = await fetch(`${BASE}/health`); up = r.ok; } catch (_) {}
      if (!up) await new Promise((r) => setTimeout(r, 200));
    }
    check('server health endpoint', up);

    // 1. Preflight
    const pre = await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
    check('preflight shape', pre.body.ok === true && pre.body.protocolVersion === 'v1', JSON.stringify(pre.body));
    check('preflight response signed', pre.sig === sign(pre.rawText));

    // 2. Bad signature rejected
    const bad = await post(envelope('gk_99_zz'), { badSig: true });
    check('bad inbound signature -> 401', bad.status === 401);

    // 3. APPROVE case — all checks pass
    const approveEnv = envelope('gk_24_9d1');
    const t0 = Date.now();
    const ap = await post(approveEnv);
    const apMs = Date.now() - t0;
    check('approve: decision', ap.body.decision === 'APPROVE', ap.body.decision + '/' + ap.body.reason_code);
    check('approve: proof attached', !!ap.body.proof && Array.isArray(ap.body.public_signals));
    check('approve: 13 public signals', ap.body.public_signals && ap.body.public_signals.length === 13);
    check('approve: decision signal = 1', ap.body.public_signals && ap.body.public_signals[11] === '1');
    check('approve: response signed', ap.sig === sign(ap.rawText));
    check('approve: within 60s deadline', apMs < 60000, apMs + 'ms');
    const vAp = cliVerify('approve', ap.body);
    check('approve: snarkjs groth16 verify', /OK/.test(vAp), vAp.trim().split('\n').pop());

    // 4. Idempotent replay — byte-identical envelope again (a platform retry
    //    resends the same bytes), identical response expected
    const replay = await post(approveEnv);
    check('idempotent replay returns identical body', replay.rawText === ap.rawText);

    // 5. REJECT case — recipient mismatch trap
    const rj = await post(envelope('gk_25_7ab', {}, { condition_recipient: ADDR2 }));
    check('reject: decision', rj.body.decision === 'REJECT', rj.body.decision + '/' + rj.body.reason_code);
    check('reject: reason RECIPIENT_MISMATCH', rj.body.reason_code === 'RECIPIENT_MISMATCH');
    check('reject: proof attached', !!rj.body.proof && Array.isArray(rj.body.public_signals));
    check('reject: decision signal = 0', rj.body.public_signals && rj.body.public_signals[11] === '0');
    const vRj = cliVerify('reject-recipient', rj.body);
    check('reject: snarkjs groth16 verify', /OK/.test(vRj), vRj.trim().split('\n').pop());

    // 6. REJECT case — VK substitution trap
    const vkSub = await post(envelope('gk_26_1ff', {}, { proof_vk: '0xaaaaaaaabbbbbbbbccccccccdddddddd00000000111111112222222233333333' }));
    check('vk-substitution: decision REJECT', vkSub.body.decision === 'REJECT', vkSub.body.reason_code);
    check('vk-substitution: reason VK_SUBSTITUTION', vkSub.body.reason_code === 'VK_SUBSTITUTION');
    if (vkSub.body.proof) {
      const vVk = cliVerify('reject-vk', vkSub.body);
      check('vk-substitution: snarkjs groth16 verify', /OK/.test(vVk));
    }
  } finally {
    server.kill('SIGTERM');
  }
  const failed = results.filter(([, ok]) => !ok);
  console.log(`\n==== SUMMARY: ${results.length - failed.length}/${results.length} checks passed ====`);
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error('TEST HARNESS ERROR', e); process.exit(2); });

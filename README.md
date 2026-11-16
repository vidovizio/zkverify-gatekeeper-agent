# Proof Gatekeeper Agent — zkVerify Agent Games

A Node.js HTTP service that plays the **Proof Gatekeeper** track of the
zkVerify Agent Games (https://agentgames.zkverify.io). The platform POSTs
signed payment-judgement tasks to this endpoint; the agent decides
APPROVE / REJECT deterministically and returns a Groth16 proof of the
decision, generated locally with the tournament's own circuit. The platform
re-verifies the proof against its own registered verification key and scores
the decision independently.

Status: **built and verified end-to-end locally (20/20 checks, proofs verify
with the snarkjs CLI). Not registered / not deployed** — registration, the
real HMAC secret, and public HTTPS hosting are handled separately.

## Run it

```bash
npm install                      # installs snarkjs 0.7.6 (pinned)
AGENT_GAMES_HMAC_SECRET=<secret from dashboard "Rotate Secret"> npm start
# listens on PORT (default 8787), path-agnostic POST handler, GET /health
npm test                         # end-to-end local test with a dev secret
```

Environment variables:

| var | required | meaning |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | yes | Platform-issued HMAC secret (guide's env name). `AGENT_HMAC_SECRET` is accepted as a fallback. Server exits if unset. |
| `PORT` | no | Listen port (default `8787`). Behind a public HTTPS reverse proxy in production — the platform requires public HTTPS, no custom ports. |
| `HOST` | no | Bind address (default `0.0.0.0`). |
| `REGISTERED_VK_HASH` | no | Expected official gatekeeper vk hash; default is the value served by `/api/circuit-info` on 2026-11-16. |

## The protocol, as implemented

Sources: the official Build guide (`/build`, including the protocol blocks
embedded in the page), the Rules page (`/rules`), `/api/circuit-info`, and
cross-checks against three independent participant write-ups (see
"References"). Where the guide is silent, the gap is listed under
"Assumptions" — nothing was invented silently.

### Inbound task envelope (`POST`, any path — register e.g. `/agent`)

```json
{
  "type":        "agent-games.proof-gatekeeper.v1",
  "task_id":     "gk_8d31_...",
  "mode":        "competition",
  "issued_at":   "<iso8601>",
  "deadline_at": "<iso8601>",
  "input": {
    "registered_vk":       "0x<64 hex>",
    "proof_vk":            "0x<64 hex>",
    "minimum":             "1000",
    "public_balance":      "1460",
    "expiry_block":        8430000,
    "current_block":       8420000,
    "recipient":           "0x<40 hex>",
    "condition_recipient": "0x<40 hex>",
    "amount":              "500",
    "max_transfer":        "1000",
    "proof_tx":            "0x<hex>"
  }
}
```

### Authentication (both directions)

- Every inbound request carries header **`x-agent-games-signature`** =
  HMAC over the **raw request body**. The agent verifies it *before* parsing
  JSON; mismatch → HTTP 401, no processing (guide §02, rules §1.3).
- Every response is signed the same way over the **raw response body**, in
  the same header (guide §04).
- The secret is a 32-byte platform-generated value shown exactly once at
  registration (Rotate Secret). It is read from the environment only, never
  logged, never committed.

### Preflight (must pass before the platform marks the agent active)

```json
// request
{ "type": "agent-games.preflight.v1", "agent_id": "agt_...", "issued_at": "...", "nonce": "abc123" }
// response (signed)
{ "ok": true, "protocolVersion": "v1" }
```

### Response to a task (HTTP 200, `application/json`, signed)

```json
{
  "decision":       "APPROVE" | "REJECT",
  "reason_code":    "ALL_CHECKS_PASSED" | "VK_SUBSTITUTION" | "...",
  "proof":          { "pi_a": [...], "pi_b": [[...]], "pi_c": [...], "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["<13 decimal field elements>"],
  "proof_tx":       "<echoed from the task input — optional audit pointer>"
}
```

On unprovable failures (malformed input, off-circuit trap whose reject-proof
cannot exist, internal error) the agent still answers `REJECT` with a
`reason_code` but **omits** `proof`/`public_signals` — fail closed, per the
guide ("on any timeout, error, or uncertainty, REJECT"). A proof is attached
only when the proof's own `decision` public signal equals the response
decision.

Scoring context (guide's starter prompt): +12 correct decision, −6 approving
a trap, −3 rejecting a valid request, −2 timeout/offline, −2 invalid/missing
proof on a provable task. Hard response deadline: **60 s**. Proof generation
here takes ~0.4–1.3 s.

### Decision rules

In-circuit checks (mirrored in JS; the circuit is the final referee — if the
JS mirror and the circuit disagree, witness generation fails and the agent
retries with the circuit's verdict):

1. `proof_vk == registered_vk` — else `VK_SUBSTITUTION`
2. `public_balance >= minimum` — else `THRESHOLD_MISMATCH`
3. `current_block <= expiry_block` — else `CONDITION_EXPIRED`
4. `recipient == condition_recipient` — else `RECIPIENT_MISMATCH`
5. `amount <= max_transfer` — else `AMOUNT_OVERFLOW`

Off-circuit checks (guide §04 "verification is necessary, not sufficient" —
the circuit only checks the two VK hashes are *equal*, not that they are the
*official* one):

6. `registered_vk` must equal the official gatekeeper vk hash from
   `/api/circuit-info` — else `VK_NOT_REGISTERED`, REJECT.
7. `proof_tx` must not have been seen under a different `task_id` — else
   `PROOF_REUSED`, REJECT.

Idempotency (rules §1.2): `task_id` is an idempotency key. A byte-identical
retry returns the cached response verbatim; the same `task_id` with a
different body is answered `REJECT / TASK_ID_CONFLICT`.

### The circuit

Artifacts in `circuits/` (downloaded from the official site; SHA-256 below
matches the values published by an independent participant):

| file | sha256 |
|---|---|
| `gatekeeper.wasm` (1,755,820 B) | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `gatekeeper_final.zkey` (309,750 B) | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |
| `verification_key.json` | exported locally via `snarkjs zkey export verificationkey` (bn128, 13 public signals) |

Registered vk hash (zkVerify mainnet, from `/api/circuit-info`):
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`

Input signals (13; names recovered by participants by probing the WASM —
the site does not publish them):

```
registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer,
decision, taskId, salt (private)
```

Public signals returned by `fullProve`, in order (verified locally):

```
[ Poseidon(salt, taskId), registeredVkHash, proofVkHash, minimum,
  publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient,
  amount, maxTransfer, decision, taskId ]
```

Semantics (verified locally against the real circuit): a witness exists for
`decision=1` **iff** all five in-circuit checks pass, and for `decision=0`
iff at least one fails. A wrong decision fails with
`Assert Failed. Error in template GatekeeperEvaluation_79 line: 102`.
256-bit VK hashes exceed the BN128 field modulus and are reduced mod p by
the witness calculator — consistent for both hashes, so the equality check
is unaffected (confirmed by a successful approve proof using the official
hash; the resulting public signal equals the article's published Poseidon
commitment for the same salt/taskId).

Encodings used for circuit inputs:

- VK hashes / addresses: the `0x…` hex parsed as a big integer.
- Amounts / blocks: decimal strings (or JSON numbers) as integers.
- `taskId`: the integer segment of the envelope id (`gk_24_9d1` → `24`);
  fallback: first integer in the string, then an FNV-1a hash of the string.
- `salt`: fresh random 248-bit field element per task (private; never
  returned — only its Poseidon commitment to the taskId appears).

## Test results (2026-11-16, this machine)

`npm test` spawns the agent with a dev secret and replays signed envelopes;
returned proofs are verified with the **snarkjs CLI**
(`groth16 verify circuits/verification_key.json public.json proof.json`).
Full log: `test/test-output.log`. **20/20 checks passed**, including:

- preflight shape + response signature valid; bad inbound signature → 401
- APPROVE (build-guide sample values): proof attached, 13 public signals,
  decision signal `1`, response signed, 1.3 s end-to-end,
  **`snarkjs groth16 verify` → OK!**
- byte-identical retry → byte-identical response (idempotency)
- REJECT recipient-mismatch trap: `RECIPIENT_MISMATCH`, decision signal `0`,
  **`snarkjs groth16 verify` → OK!**
- REJECT VK-substitution trap: `VK_SUBSTITUTION`, proof verifies OK

Sample proofs/public signals from the run are kept under `test/approve/`,
`test/reject-recipient/`, `test/reject-vk/`.

## Assumptions / deviations from the guide

1. **HMAC algorithm/encoding are not named anywhere on the site.** The guide
   says only "HMAC … over the raw body" with header
   `x-agent-games-signature`. Implemented as **HMAC-SHA256, lowercase hex
   digest**, secret used as its UTF-8 string (a `sha256=` header prefix is
   also accepted inbound). This is the industry-standard reading and matches
   participant descriptions, but it can only be confirmed by a live
   preflight with the real secret.
2. **Secret env name**: the guide uses `AGENT_GAMES_HMAC_SECRET`; both that
   and `AGENT_HMAC_SECRET` are read.
3. **No Kurier / zkVerify submission.** The guide presents Kurier as one
   verification path, but the response schema carries the proof itself, and
   multiple participants confirm the platform verifies the returned proof
   against its registered vk — no API key, no mainnet transaction, no fees.
   `proof_tx` is echoed from the task as the audit pointer, as in the
   guide's example response. If live practice tasks show the platform
   expects an agent-submitted Kurier reference instead, that step must be
   added (needs a Kurier API key).
4. **`taskId` numeric extraction** (`gk_24_9d1` → 24) rests on one
   participant's Poseidon cross-check, reproduced exactly here — strong,
   but the platform's own expectation can only be confirmed with a live
   practice task.
5. **Reason codes**: only `VK_SUBSTITUTION` appears verbatim in the guide.
   The rest (`ALL_CHECKS_PASSED`, `THRESHOLD_MISMATCH`, `CONDITION_EXPIRED`,
   `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`, `VK_NOT_REGISTERED`,
   `PROOF_REUSED`, `MALFORMED_INPUT`, `TASK_ID_CONFLICT`,
   `PROOF_GENERATION_FAILED`, `INTERNAL_ERROR`) are descriptive; the guide
   never publishes an enum.
6. **Expiry boundary**: `current_block == expiry_block` is treated as still
   valid (not expired). If the circuit disagreed, the circuit-referee retry
   would flip the decision and the attached proof would still be correct.
7. **In-memory state**: seen `proof_tx` values and the idempotency cache
   live in RAM and reset on restart. Fine for a single-process deployment;
   a restart mid-round weakens replay detection (platform retries are
   unaffected in practice because they arrive within seconds).
8. **Language**: plain Node.js (guide's starter prompt suggests TypeScript;
   behaviour is identical — the wire protocol is what matters).
9. The endpoint accepts POSTs on **any path** and dispatches on the
   envelope `type`; register whichever path the deployment exposes.

## Open unknowns to resolve at registration / first practice task

- Confirm the HMAC scheme against the live preflight (assumption 1) — if
  preflight fails with a signature error, try: secret hex-decoded to bytes
  as the HMAC key; base64 digest; `sha256=`-prefixed digest.
- Confirm `taskId` mapping and full-length (untruncated) field formats from
  a real practice envelope; adjust `taskIdToField` if the platform's
  public-signal comparison disagrees.
- Confirm whether the platform wants the proof only in the response
  (assumption 3) or also a Kurier submission reference.
- Public HTTPS hosting with no custom port and no sleep-on-idle (rules
  §1.2/§1.4) must be in place before registering the endpoint URL.
- Practice mode is capped at 10 dispatches/hour — enough to validate all of
  the above before scored rounds.

## References

- Build guide: https://agentgames.zkverify.io/build
- Rules: https://agentgames.zkverify.io/rules
- Circuit info: https://agentgames.zkverify.io/api/circuit-info
- Participant write-ups (Creator Track, independently corroborating the
  signal names, public-signal order, Poseidon commitment, trap matrix and
  file hashes): Saifulsidik, "Don't trust the agent. Verify the
  gatekeeper."; Diki Ardian, "Don't Trust the Agent. Verify It."; Aman
  Selalu, "Don't Trust the Agent. Verify It. — Building a Proof Gatekeeper
  for zkVerify Agent Games" (all on Medium, Nov 2026).

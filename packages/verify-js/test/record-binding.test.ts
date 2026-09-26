// The close record must seal this session's single, chained session.close
// and be signed by the session's signer; signers can't mix pinned and
// package-only keys. Security release batch; see the private advisory.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { verifyPackage, type PackageFiles } from '../src/index.js';

const ROOT = join(__dirname, '../../../tests/vectors/packages');
const td = new TextDecoder();
const te = new TextEncoder();
const J = (b: string | Uint8Array) => JSON.parse(typeof b === 'string' ? b : td.decode(b));
const b64u = (b: Buffer) => b.toString('base64url');
const sha = (b: Uint8Array) => crypto.createHash('sha256').update(b).digest();
const pae = (t: string, p: Buffer) =>
  Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(t)} ${t} ${p.length} `), p]);

function readPackage(dir: string): PackageFiles {
  const files: PackageFiles = {};
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else files[relative(dir, p)] = new Uint8Array(readFileSync(p));
    }
  };
  walk(dir);
  return files;
}

const att = crypto.generateKeyPairSync('ed25519');
const ATT = 'key_a77ac4e2a77ac4e2';
const attPub = 'ed25519:' + (att.publicKey.export({ format: 'jwk' }).x as string);

function sign(type: string, stmt: unknown) {
  const p = Buffer.from(JSON.stringify(stmt));
  const env = { payload: b64u(p), payloadType: type, signatures: [{ keyid: ATT, sig: b64u(crypto.sign(null, pae(type, p), att.privateKey)) }] };
  const d = sha(pae(type, p)).toString('hex');
  return { env, id: 'art_' + d.slice(0, 32), digest: 'sha256:' + d };
}

// RFC 9162 tree over artifact ids, to keep structure valid after an edit.
const leaf = (id: string) => sha(Buffer.concat([Buffer.from([0]), Buffer.from(id)]));
const node = (l: Buffer, r: Buffer) => sha(Buffer.concat([Buffer.from([1]), l, r]));
const kSplit = (n: number) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const mth = (L: Buffer[]): Buffer => (L.length === 1 ? L[0] : node(mth(L.slice(0, kSplit(L.length))), mth(L.slice(kSplit(L.length)))));
const path = (m: number, L: Buffer[]): { direction: string; hash: string }[] => {
  if (L.length <= 1) return [];
  const k = kSplit(L.length);
  return m < k
    ? [...path(m, L.slice(0, k)), { direction: 'Right', hash: mth(L.slice(k)).toString('hex') }]
    : [...path(m - k, L.slice(k)), { direction: 'Left', hash: mth(L.slice(0, k)).toString('hex') }];
};
function remerkle(r: any) {
  const L = r.artifacts.map((a: any) => leaf(a.artifact_id));
  r.merkle.leaf_count = L.length;
  r.merkle.root = 'mroot_' + mth(L).toString('hex');
  r.merkle.inclusion_proofs = r.artifacts.map((a: any, i: number) => ({
    artifact_id: a.artifact_id,
    leaf_index: i,
    proof: { ...r.merkle.inclusion_proofs[0].proof, leaf_index: i, leaf_hash: leaf(a.artifact_id).toString('hex'), path: path(i, L) },
  }));
}

const base = readPackage(join(ROOT, 'honest/basic'));
const honestKeys: Record<string, string> = J(base['keys.json']).keys;
const bothPinned = { pinnedKeys: { ...honestKeys, [ATT]: attPub } };
const keysWithAttacker = () => {
  const k = J(base['keys.json']);
  k.keys[ATT] = attPub;
  return JSON.stringify(k);
};
const attackerRecord = (receiptBytes: Uint8Array, type?: string) => {
  const honest = J(base['record.json']);
  const stmt = J(Buffer.from(honest.payload, 'base64url'));
  stmt.payload.receipt_digest = 'sha256:' + sha(receiptBytes).toString('hex');
  return JSON.stringify(sign(type ?? honest.payloadType, stmt).env);
};

describe('close record binding', () => {
  it('a rewritten receipt under a record signed by another pinned key fails', async () => {
    const r = J(base['receipt.json']);
    r.session.narrative = { ...(r.session.narrative ?? {}), headline: 'rewritten' };
    const rb = te.encode(JSON.stringify(r, null, 2));
    const files = { ...base, 'receipt.json': rb, 'keys.json': keysWithAttacker(), 'record.json': attackerRecord(rb) };
    for (const o of [{}, { pinnedKeys: honestKeys }, bothPinned]) {
      expect((await verifyPackage(files, o)).verdict).toBe('failed');
    }
  });

  it('a record that is not a session.v1 receipt fails', async () => {
    const files = { ...base, 'keys.json': keysWithAttacker(), 'record.json': attackerRecord(base['receipt.json'] as Uint8Array, 'application/vnd.treeship.action.v1+json') };
    expect((await verifyPackage(files, bothPinned)).verdict).toBe('failed');
  });

  it('a second session.close fails', async () => {
    const r = J(base['receipt.json']);
    const c = sign('application/vnd.treeship.action.v1+json', {
      type: 'treeship/action/v1',
      timestamp: r.session.ended_at,
      actor: 'agent://vector',
      action: 'session.close',
      meta: { session_id: r.session.id },
    });
    r.artifacts.push({ artifact_id: c.id, payload_type: c.env.payloadType, digest: c.digest });
    remerkle(r);
    const rb = te.encode(JSON.stringify(r, null, 2));
    const files = { ...base, 'receipt.json': rb, 'keys.json': keysWithAttacker(), [`artifacts/${c.id}.json`]: JSON.stringify(c.env), 'record.json': attackerRecord(rb) };
    const res = await verifyPackage(files, bothPinned);
    expect(res.verdict).toBe('failed');
    expect(res.checks.find((c) => c.step === 'structure')?.status).toBe('pass');
  });

  it('pinned and package-only signers mixed fails', async () => {
    const files = { ...base, 'keys.json': keysWithAttacker(), 'record.json': attackerRecord(base['receipt.json'] as Uint8Array) };
    const res = await verifyPackage(files, { pinnedKeys: honestKeys });
    expect(res.verdict).toBe('failed');
  });

  it('the honest package still verifies', async () => {
    expect((await verifyPackage(base, { pinnedKeys: honestKeys })).verdict).toBe('verified');
    expect((await verifyPackage(base)).verdict).toBe('signatures-pass');
  });
});

describe('record_key', () => {
  const rec = crypto.generateKeyPairSync('ed25519');
  const REC = 'key_7ec07ec07ec07ec0';
  const recPub = 'ed25519:' + (rec.publicKey.export({ format: 'jwk' }).x as string);
  const signWith = (type: string, stmt: unknown, kid: string, key: crypto.KeyObject) => {
    const p = Buffer.from(JSON.stringify(stmt));
    return { payload: b64u(p), payloadType: type, signatures: [{ keyid: kid, sig: b64u(crypto.sign(null, pae(type, p), key)) }] };
  };

  // A whole session signed by the test key: start -> close, the close naming
  // a separate record key in the given place, and a record signed by it.
  function session(recordKeyAt: 'meta' | 'top', opts: { rkEncoding?: 'cli' | 'bare'; recInKeys?: boolean } = {}) {
    const r = J(base['receipt.json']);
    const sid = r.session.id;
    const start = sign('application/vnd.treeship.action.v1+json', {
      type: 'treeship/action/v1', timestamp: r.session.started_at, actor: 'agent://vector', action: 'session.start',
      meta: { session_id: sid, session_start: true },
    });
    const rk = { key_id: REC, public_key: opts.rkEncoding === 'bare' ? recPub.slice('ed25519:'.length) : recPub };
    const close = sign('application/vnd.treeship.action.v1+json', {
      type: 'treeship/action/v1', timestamp: r.session.ended_at, actor: 'agent://vector', action: 'session.close',
      parentId: start.id,
      meta: { session_id: sid, session_close: true, ...(recordKeyAt === 'meta' ? { record_key: rk } : {}) },
      ...(recordKeyAt === 'top' ? { record_key: rk } : {}),
    });
    r.artifacts = [start, close].map((a) => ({ artifact_id: a.id, payload_type: a.env.payloadType, digest: a.digest }));
    remerkle(r);
    const rb = te.encode(JSON.stringify(r, null, 2));
    const record = signWith('application/vnd.treeship.receipt.v1+json', {
      type: 'treeship/receipt/v1', timestamp: r.session.ended_at, system: 'system://treeship-session',
      subject: { artifactId: close.id }, kind: 'session.v1',
      payload: { session_id: sid, receipt_digest: 'sha256:' + sha(rb).toString('hex') },
    }, REC, rec.privateKey);
    const files: PackageFiles = {
      'receipt.json': rb,
      'keys.json': JSON.stringify({ schema: 'treeship/package-keys/v1', keys: { [ATT]: attPub, ...(opts.recInKeys === false ? {} : { [REC]: recPub }) } }),
      'record.json': JSON.stringify(record),
      [`artifacts/${start.id}.json`]: JSON.stringify(start.env),
      [`artifacts/${close.id}.json`]: JSON.stringify(close.env),
    };
    return files;
  }
  const pins = { pinnedKeys: { [ATT]: attPub, [REC]: recPub } };

  it('a record signed by the key the close names at meta.record_key is accepted', async () => {
    const res = await verifyPackage(session('meta'), pins);
    expect(res.verdict, JSON.stringify(res.checks)).toBe('verified');
  });

  it('a record_key anywhere else in the close is not', async () => {
    expect((await verifyPackage(session('top'), pins)).verdict).toBe('failed');
  });

  it('the record key is vouched for by the close: pinning the session signer alone verifies', async () => {
    const onlyAtt = { pinnedKeys: { [ATT]: attPub } };
    for (const recInKeys of [true, false]) {
      const res = await verifyPackage(session('meta', { recInKeys }), onlyAtt);
      expect(res.verdict, JSON.stringify(res.checks)).toBe('verified');
    }
  });

  it('a record_key not in the CLI encoding (ed25519:<base64url>) fails closed', async () => {
    expect((await verifyPackage(session('meta', { rkEncoding: 'bare' }), { pinnedKeys: { [ATT]: attPub } })).verdict).toBe('failed');
  });
});

describe('envelope signatures', () => {
  it('a second signature under the same key id fails, even when the first is valid', async () => {
    const r = J(base['receipt.json']);
    const id = r.artifacts[1].artifact_id;
    const env = J(base[`artifacts/${id}.json`]);
    env.signatures.push({ keyid: env.signatures[0].keyid, sig: b64u(Buffer.alloc(64, 7)) });
    const files = { ...base, [`artifacts/${id}.json`]: JSON.stringify(env) };
    const res = await verifyPackage(files, { pinnedKeys: honestKeys });
    expect(res.verdict).toBe('failed');
  });
});

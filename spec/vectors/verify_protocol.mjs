// SPDX-License-Identifier: Apache-2.0
// Copyright Contributors to the Universal Plug Protocol project
// Independent check of spec/vectors/protocol.json, written from SPEC.md with Node's standard library only.
// Re-derives salted, bridge, and batch commitments, RFC 9162 roots and inclusion proofs, attestation
// statements, and the reserved commitment domain; verifies Ed25519 and P-256 proofs over statements and
// issuer binding for did:key.
// Usage: node spec/vectors/verify_protocol.mjs
import { createHash, createPublicKey, verify, ECDH } from "node:crypto";
import { readFileSync } from "node:fs";

const vectors = JSON.parse(readFileSync(new URL("./protocol.json", import.meta.url), "utf8"));

const canon = (v) =>
  v === null || typeof v !== "object"
    ? JSON.stringify(v)
    : Array.isArray(v)
      ? "[" + v.map(canon).join(",") + "]"
      : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";

const ALG = { "sha-256": "sha256", "sha3-256": "sha3-256", sm3: "sm3" };
const H = (alg, ...parts) => {
  const h = createHash(ALG[alg]);
  for (const p of parts) h.update(p);
  return h.digest();
};
const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (s) => Buffer.from(s, "hex");

const factBytes = (f) =>
  "json" in f ? Buffer.from(canon(f.json), "utf8") : "hex" in f ? unhex(f.hex) : Buffer.from(f.text, "utf8");

// RFC 9162 section 2.1.1
const leafHash = (alg, leaf) => H(alg, Buffer.from([0]), leaf);
const nodeHash = (alg, l, r) => H(alg, Buffer.from([1]), l, r);
const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
const mth = (alg, leaves) =>
  leaves.length === 0 ? H(alg, Buffer.alloc(0))
    : leaves.length === 1 ? leafHash(alg, leaves[0])
      : nodeHash(alg, mth(alg, leaves.slice(0, split(leaves.length))), mth(alg, leaves.slice(split(leaves.length))));

// RFC 9162 section 2.1.3.2
const verifyInclusion = (alg, leaf, index, size, path, root) => {
  if (!(index >= 0 && index < size)) return false;
  let fn = BigInt(index), sn = BigInt(size - 1), r = leaf;
  for (const p of path) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHash(alg, p, r);
      while ((fn & 1n) === 0n && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
    } else {
      r = nodeHash(alg, r, p);
    }
    fn >>= 1n; sn >>= 1n;
  }
  return sn === 0n && r.equals(root);
};

// did:key: base58btc multibase, unsigned-varint multicodec prefix
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58decode = (s) => {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error("not base58btc");
    n = n * 58n + BigInt(i);
  }
  let h = n === 0n ? "" : n.toString(16);
  if (h.length % 2) h = "0" + h;
  return Buffer.concat([Buffer.alloc(s.length - s.replace(/^1+/, "").length), unhex(h)]);
};
const b58encode = (bytes) => {
  let n = BigInt("0x" + (hex(bytes) || "0")), out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  return "1".repeat(zeros) + out;
};
const MULTICODEC = { ed25519: [0xed, 0x01], "ecdsa-p256": [0x80, 0x24] };
// Canonical did:key only (SPEC.md, Signature suites): a 32-byte Ed25519 key or a 33-byte compressed point,
// spelled so that re-encoding gives the same identifier.
const parseDidKey = (did) => {
  const base = did.split("#")[0];
  if (!base.startsWith("did:key:z")) throw new Error("not a did:key");
  const raw = b58decode(base.slice("did:key:z".length));
  for (const [alg, prefix] of Object.entries(MULTICODEC)) {
    if (raw[0] === prefix[0] && raw[1] === prefix[1]) {
      const key = raw.subarray(2);
      if (alg === "ed25519" ? key.length !== 32 : key.length !== 33 || (key[0] !== 2 && key[0] !== 3)) {
        throw new Error("non-canonical key encoding");
      }
      if ("did:key:z" + b58encode(raw) !== base) throw new Error("non-canonical did:key");
      return [alg, key];
    }
  }
  throw new Error("unsupported multicodec");
};

// Ed25519 keys of small order verify forged signatures under OpenSSL; reject them (RFC 8032 5.1.3 decoding, [8]P).
const P = 2n ** 255n - 19n;
const mod = (a) => ((a % P) + P) % P;
const pow = (b, e) => { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; };
const D = mod(-121665n * pow(121666n, P - 2n));
const SQRT_M1 = pow(2n, (P - 1n) / 4n);
const edSmallOrderOrInvalid = (key) => {
  if (key.length !== 32) return true;
  const bytes = Buffer.from(key);
  const sign = bytes[31] >> 7;
  bytes[31] &= 0x7f;
  const y = BigInt("0x" + Buffer.from(bytes).reverse().toString("hex"));
  if (y >= P) return true;
  const u = mod(y * y - 1n), v = mod(D * y * y + 1n);
  let x = mod(u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n));
  if (mod(v * x * x - u) !== 0n) {
    x = mod(x * SQRT_M1);
    if (mod(v * x * x - u) !== 0n) return true;
  }
  if (x === 0n && sign) return true;
  if (Number(x & 1n) !== sign) x = P - x;
  let [X, Y, Z] = [x, y, 1n];
  for (let i = 0; i < 3; i++) {
    const A = X * X % P, B = Y * Y % P, C = 2n * Z * Z % P, H = mod(A + B);
    const E = mod(H - (X + Y) * (X + Y)), G = mod(A - B), F = mod(C + G);
    [X, Y, Z] = [E * F % P, G * H % P, F * G % P];
  }
  return X === 0n && Y === Z;
};
const b64u = (b) => Buffer.from(b).toString("base64url");
const publicKey = (alg, raw) => {
  if (alg === "ed25519") return createPublicKey({ format: "jwk", key: { kty: "OKP", crv: "Ed25519", x: b64u(raw) } });
  const xy = ECDH.convertKey(raw, "prime256v1", undefined, undefined, "uncompressed");
  return createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256", x: b64u(xy.subarray(1, 33)), y: b64u(xy.subarray(33)) } });
};

// The statement a proof signs: the subject hash with every label a verifier acts on (SPEC.md, Statement).
const statement = (a) => ({ "plug.statement": {
  subject_hash: a.subject_hash.toLowerCase(), hash_alg: a.hash_alg, fact_type: a.fact_type, issuer: a.issuer,
  issued_at: a.issued_at, expires_at: a.expires_at ?? null, role: a.role ?? null,
  meta: Object.fromEntries(Object.entries(a.meta ?? {}).filter(([k]) => !k.startsWith("_"))),
  disclosure: a.disclosure ?? [],
} });
const statementHash = (a) => H(a.hash_alg, Buffer.from(canon(statement(a)), "utf8"));

// A proof is valid when the signature over the 32-byte statement hash verifies under the verification
// method's key and the issuer DID names that same key (SPEC.md, Signature suites).
const proofValid = (att, proof) => {
  try {
    if (!/^[0-9a-fA-F]{64}$/.test(att.subject_hash)) return false;
    const msg = statementHash(att);
    const issuer = att.issuer;
    const [keyAlg, raw] = parseDidKey(proof.verification_method);
    if (keyAlg !== proof.alg) return false;
    if (keyAlg === "ed25519" && edSmallOrderOrInvalid(raw)) return false;
    const sig = unhex(proof.sig.replace(/^0x/, ""));
    const key = publicKey(keyAlg, raw);
    const ok = keyAlg === "ed25519"
      ? verify(null, msg, key, sig)
      : verify("sha256", msg, { key, dsaEncoding: "ieee-p1363" }, sig);
    return ok && issuer.split("#")[0] === proof.verification_method.split("#")[0];
  } catch {
    return false;
  }
};

let failures = 0, checks = 0;
const expect = (cond, what) => { checks++; if (!cond) { failures++; console.error("FAIL", what); } };

for (const v of vectors.salted) {
  const fb = factBytes(v.fact);
  expect(hex(H(v.hash_alg, fb)) === v.plain, `salted plain ${v.hash_alg} ${JSON.stringify(v.fact)}`);
  expect(hex(H(v.hash_alg, unhex(v.salt), fb)) === v.subject_hash, `salted commitment ${v.hash_alg} ${JSON.stringify(v.fact)}`);
}

for (const v of vectors.bridge) {
  const c = H(v.hash_alg, Buffer.from(canon({ "plug.bridge": v.source }), "utf8"));
  expect(hex(c) === v.commitment, `bridge ${v.hash_alg} ${v.source.address}`);
}

for (const b of vectors.batches) {
  const label = `batch ${b.hash_alg} ${b.commitment} size ${b.size}`;
  const subjects = b.facts.map((f, i) =>
    b.salts ? H(b.hash_alg, unhex(b.salts[i]), factBytes(f)) : H(b.hash_alg, factBytes(f)));
  expect(subjects.every((s, i) => hex(s) === b.subjects[i]), `${label}: subjects`);
  const root = mth(b.hash_alg, subjects);
  expect(hex(root) === b.root && b.size === subjects.length, `${label}: root`);
  const bc = H(b.hash_alg, Buffer.from(canon({ "plug.batch": { root: b.root, size: b.size } }), "utf8"));
  expect(hex(bc) === b.batch_commitment, `${label}: batch commitment`);
  b.inclusion.forEach((inc, i) => expect(
    inc.index === i && verifyInclusion(b.hash_alg, leafHash(b.hash_alg, subjects[i]), inc.index, b.size, inc.path.map(unhex), root),
    `${label}: inclusion ${i}`));
}

for (const v of vectors.inclusion_negative) {
  const ok = verifyInclusion(v.hash_alg, leafHash(v.hash_alg, unhex(v.subject_hash)), v.index, v.size, v.path.map(unhex), unhex(v.root));
  expect(!ok, `inclusion negative: ${v.case}`);
}

for (const v of vectors.statements) {
  const a = v.attestation;
  expect(canon(statement(a)) === v.statement, `statement ${a.hash_alg} ${a.fact_type}`);
  expect(hex(statementHash(a)) === v.statement_hash, `statement hash ${a.hash_alg} ${a.fact_type}`);
}

for (const v of vectors.proofs) {
  expect(proofValid(v.attestation, v.proof) === v.valid, `proof ${v.proof.alg}: ${v.case}`);
}

for (const v of vectors.reserved) {
  const refused = factBytes(v.fact).subarray(0, 7).equals(Buffer.from('{"plug.', "utf8"));
  expect(refused === v.refused, `reserved domain: ${JSON.stringify(v.fact)}`);
}

if (failures) {
  console.error(`protocol vectors: ${failures} of ${checks} checks failed`);
  process.exit(1);
}
console.log(`vectors: protocol.json verified independently (${checks} checks)`);

// SPDX-License-Identifier: Apache-2.0
// Copyright Contributors to the Universal Plug Protocol project
// Regenerates spec/vectors/jcs.json with Node as the independent reference.
// RFC 8785 is defined by ECMAScript JSON.stringify and UTF-16 key order, so Node is the oracle.
// Usage: node spec/vectors/generate_jcs.mjs > spec/vectors/jcs.json
import { createHash } from "node:crypto";

const canon = (v) =>
  v === null || typeof v !== "object"
    ? JSON.stringify(v)
    : Array.isArray(v)
      ? "[" + v.map(canon).join(",") + "]"
      : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";

const fromBits = (hex) => {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt("0x" + hex));
  return view.getFloat64(0);
};

// RFC 8785 Appendix B samples plus boundary cases of the ECMAScript formatting rules.
const bits = [
  "0000000000000000", "8000000000000000", "0000000000000001", "8000000000000001",
  "7fefffffffffffff", "ffefffffffffffff", "4340000000000000", "c340000000000000",
  "4430000000000000", "44b52d02c7e14af5", "44b52d02c7e14af6", "44b52d02c7e14af7",
  "444b1ae4d6e2ef4e", "444b1ae4d6e2ef4f", "444b1ae4d6e2ef50", "3eb0c6f7a0b5ed8c",
  "3eb0c6f7a0b5ed8d", "41b3de4355555553", "41b3de4355555554", "41b3de4355555555",
  "41b3de4355555556", "41b3de4355555557", "becbf647612f3696", "43143ff3c1cb0959",
  "3ff0000000000000", "4035800000000000", "3f50624dd2f1a9fc", "3e7ad7f29abcaf48",
  "4202a05f20000000", "c202a05f20000000", "3fb999999999999a", "3fd3333333333333",
];
const numbers = bits.map((b) => ({ bits: b, canonical: JSON.stringify(fromBits(b)) }));

const objects = [
  '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}',
  '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}',
  '{"temp":21.5,"unit":"C","sensor":"alpha"}',
  '{"b":[3,{"z":1,"a":[]}],"a":{"y":2.0,"x":-0.0}}',
  '{"cargo":"\\u94dc\\u7cbe\\u77ff","port":"Shanghai","bl":"\\u65e0\\u7eb8\\u5316-001","weight_t":2500.75}',
  '{"emissions_tco2e":1.234e-4,"installation":"DE-123","period":"2026-Q3"}',
  '[]', '{}', '"plain"', '1e21', '1e-7', '100', '-1.5',
].map((text) => {
  const c = canon(JSON.parse(text));
  const h = (alg) => createHash(alg).update(c, "utf8").digest("hex");
  return { input: text, canonical: c, "sha-256": h("sha256"), "sha3-256": h("sha3-256"), sm3: h("sm3") };
});

console.log(JSON.stringify({ generator: `node ${process.version}`, rfc: "RFC 8785", numbers, objects }, null, 2));

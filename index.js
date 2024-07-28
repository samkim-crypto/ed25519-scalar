"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.signAsync = exports.sign = exports.getPublicKeyAsync = exports.getPublicKey = void 0;
const ed25519_1 = require("@noble/ed25519");
const N = ed25519_1.CURVE.n;
const G = ed25519_1.ExtendedPoint.BASE;
const err = (m = '') => { throw new Error(m); }; // error helper, messes-up stack trace
const padh = (num, pad) => num.toString(16).padStart(pad, '0');
const isu8 = (a) => (a instanceof Uint8Array ||
    (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array'));
const au8 = (a, l) => // is Uint8Array (of specific length)
 !isu8(a) || (typeof l === 'number' && l > 0 && a.length !== l) ?
    err('Uint8Array of valid length expected') : a;
const u8n = (data) => new Uint8Array(data); // creates Uint8Array
const str = (s) => typeof s === 'string'; // is string
const toU8 = (a, len) => au8(str(a) ? ed25519_1.etc.hexToBytes(a) : u8n(au8(a)), len); // norm(hex/u8a) to u8a
const b2h = (b) => Array.from(b).map(e => padh(e, 2)).join(''); // bytes to hex
const n2b_32LE = (num) => ed25519_1.etc.hexToBytes(padh(num, 32 * 2)).reverse(); // number to bytes LE
const b2n_LE = (b) => BigInt('0x' + b2h(u8n(au8(b)).reverse())); // bytes LE to num
const modL_LE = (hash) => ed25519_1.etc.mod(b2n_LE(hash), N); // modulo L; but little-endian
const getExtendedPublicKeyAsync = (priv) => sha512a(priv).then((hashed) => hash2extK(priv, hashed));
const getExtendedPublicKey = (priv) => hash2extK(priv, sha512s(priv));
const getPublicKeyAsync = (priv) => getExtendedPublicKeyAsync(toU8(priv, 32)).then(p => p.pointBytes);
exports.getPublicKeyAsync = getPublicKeyAsync;
const getPublicKey = (priv) => getExtendedPublicKey(toU8(priv, 32)).pointBytes;
exports.getPublicKey = getPublicKey;
const hash2extK = (priv, hashed) => {
    const prefix = hashed.slice(32, 64); // ignore the first 32 bytes generally used to generate scalar
    const scalar = modL_LE(priv); // interpret private key bytes directly as scalar
    const point = G.mul(scalar); // public key point
    const pointBytes = point.toRawBytes(); // point serialized to Uint8Array
    return { prefix, scalar, point, pointBytes };
};
let _shaS;
const sha512a = (...m) => ed25519_1.etc.sha512Async(...m); // Async SHA512
const sha512s = (...m) => // Sync SHA512, not set by default
 typeof _shaS === 'function' ? _shaS(...m) : err('etc.sha512Sync not set');
function hashFinish(asynchronous, res) {
    if (asynchronous)
        return sha512a(res.hashable).then(res.finish);
    return res.finish(sha512s(res.hashable));
}
const _sign = (e, rBytes, msg) => {
    const { pointBytes: P, scalar: s } = e;
    const r = modL_LE(rBytes);
    const R = G.mul(r).toRawBytes(); // R = [r]B
    const hashable = ed25519_1.etc.concatBytes(R, P, msg); // dom2(F, C) || R || A || PH(M)
    const finish = (hashed) => {
        const S = ed25519_1.etc.mod(r + modL_LE(hashed) * s, N); // S = (r + k * s) mod L; 0 <= s < l
        return au8(ed25519_1.etc.concatBytes(R, n2b_32LE(S)), 64); // 64-byte sig: 32b R.x + 32b LE(S)
    };
    return { hashable, finish };
};
const signAsync = async (msg, privKey) => {
    const m = toU8(msg); // RFC8032 5.1.6: sign msg with key async
    const e = await getExtendedPublicKeyAsync(toU8(privKey, 32)); // pub,prfx
    const rBytes = await sha512a(e.prefix, m); // r = SHA512(dom2(F, C) || prefix || PH(M))
    return hashFinish(true, _sign(e, rBytes, m)); // gen R, k, S, then 64-byte signature
};
exports.signAsync = signAsync;
const sign = (msg, privKey) => {
    const m = toU8(msg); // RFC8032 5.1.6: sign msg with key sync
    const e = getExtendedPublicKey(toU8(privKey, 32)); // pub,prfx
    const rBytes = sha512s(e.prefix, m); // r = SHA512(dom2(F, C) || prefix || PH(M))
    return hashFinish(false, _sign(e, rBytes, m)); // gen R, k, S, then 64-byte signature
};
exports.sign = sign;

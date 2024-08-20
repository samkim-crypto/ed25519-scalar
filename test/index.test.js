import { deepStrictEqual } from 'node:assert';
import { should } from 'micro-should';
import { hexToBytes } from '@noble/hashes/utils';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import * as edScalar from '../index.js';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
edScalar.sha.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

function to32Bytes(numOrStr) {
    let hex = typeof numOrStr === 'string' ? numOrStr : numOrStr.toString(16);
    return hexToBytes(hex.padStart(64, '0'));
}

should('ed25519-scalar sign verifies w.r.t. regular signature verification', () => {
    const msg = hexToBytes('874f9960c5d2b7a9b5fad383e1ba44719ebb743a');

    const privKey = to32Bytes('a665a45920422f9d417e4867ef');
    const publicKey = edScalar.getPublicKey(privKey);

    const signature = edScalar.sign(msg, privKey);
    deepStrictEqual(ed.verify(signature, msg, publicKey), true);
});

should.run();

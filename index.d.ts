type Bytes = Uint8Array;
type Hex = Bytes | string;
declare const getPublicKeyAsync: (priv: Hex) => Promise<Bytes>;
declare const getPublicKey: (priv: Hex) => Bytes;
declare const signAsync: (msg: Hex, privKey: Hex) => Promise<Bytes>;
declare const sign: (msg: Hex, privKey: Hex) => Bytes;
export { getPublicKey, getPublicKeyAsync, sign, signAsync };

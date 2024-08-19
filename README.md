# ed25519-scalar

Extension to the [noble-ed25519](https://github.com/paulmillr/noble-ed25519)
library, which provides an interface to sign directly from a scalar
representation of an ed25519 private key.

## Background

The ed25519 signature scheme is an instantiation of the
[EDDSA](https://en.wikipedia.org/wiki/EdDSA) (specified in
[RFC8032](https://datatracker.ietf.org/doc/html/rfc8032)), which itself is an
instantiation of the
[Schnorr signature](https://en.wikipedia.org/wiki/Schnorr_signature) scheme.
In the traditional Schnorr signature scheme, a private key is defined as a
scalar associated with a public key curve point with respect to a fixed
generator of the underlying elliptic curve. The
[RFC8032](https://datatracker.ietf.org/doc/html/rfc8032) standard tweaks the
traditional Schnorr scheme by defining the private key as a 32-byte seed to the
private key scalar value. The public key derivation and signing algorithm is
augmented with an extra step that first hashes the private key seed to derive
the scalar value.

There are some applications of Schnorr signature scheme that is not completely
compatible with [RFC8032](https://datatracker.ietf.org/doc/html/rfc8032) due
to this distinction in the private key representation. One example of these
applications is joint signing through MPC. A number of MPC signing protocols
(e.g. [FROST](https://eprint.iacr.org/2020/852)) for the Schnorr signature
scheme have been developed. However, these protocols crucially makes use of the
fact that the private key is represented as a scalar.

Since the ed25519 signature scheme is a variant of the Schnorr signature
scheme, its signature verification algorithm can still verify the signatures
that are produced via MPC. The main incompatible algorithm is the signing
algorithm, which takes in private seeds rather than private scalars as input.

This library tweaks the signing algorithm of the
[noble-ed25519](https://github.com/paulmillr/noble-ed25519) library so that
the signing function works directly with the scalar representation of the
private key.

## Status

This experimental library is still under active development and is not fit for
production use.

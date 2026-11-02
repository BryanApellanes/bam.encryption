# bam.encryption

Asymmetric and symmetric cryptography for the Bam framework, built on BouncyCastle: key pairs
(`RsaPublicPrivateKeyPair`, `EccPublicPrivateKeyPair`), public/private key wrappers with PEM
conversion (`RsaPublicKey`, `EccPublicKey`, `Pem`), signatures over text
(`ISignatureProvider`), certificates (`CertificateIssuer`), and encryption transformers.

## COSE keys and CBOR (`Bam.Encryption.Cose`)

WebAuthn authenticators hand a relying party its credential public key as a COSE_Key inside a
CBOR attestation object. This namespace decodes that subset without a third-party CBOR library:

- `CborReader.Read(bytes)` decodes one definite-length CBOR item (RFC 8949) into a `CborValue`
  tree (`CborInteger`, `CborBytes`, `CborText`, `CborArray`, `CborMap`, `CborSimple`). It is
  strict: indefinite lengths, duplicate map keys, non-integer/text keys, integers outside
  `long`, invalid UTF-8, truncated input, trailing bytes and nesting deeper than
  `CborReader.MaxDepth` raise `CborFormatException`. Tags are skipped transparently.
  `Read(bytes, out int consumed)` decodes a prefix and reports its length.
- `CborWriter.Encode(value)` is the inverse, emitting shortest-form definite-length CBOR.
- `CoseKey.Parse(bytes)` / `CoseKey.From(map)` parse a COSE_Key for `CoseAlgorithm.ES256`,
  `ES384`, `ES512` (EC2 on P-256/P-384/P-521) or `RS256` (RSA, 2048-bit minimum).
  `ToPublicKey()` returns the framework `EccPublicKey` (point validated on the curve) or
  `RsaPublicKey`; `FromEcc` / `FromRsa` / `ToCbor` go the other way.
- `CoseAlgorithms` maps each algorithm to its BouncyCastle signer name, curve and key type.

## Detached signatures over binary payloads

`ISignatureProvider.VerifySignature` verifies signatures over UTF-8 text. For payloads that are
not text, such as WebAuthn's `authenticatorData || SHA-256(clientDataJSON)`, use
`IDetachedSignatureVerifier`:

```csharp
IDetachedSignatureVerifier verifier = new DetachedSignatureVerifier();
ISignatureVerification result = verifier.Verify(payload, signatureBytes, publicKey,
    CoseAlgorithms.SignerName(CoseAlgorithm.ES256));   // "SHA-256withECDSA"
```

`Verify` never throws for a bad signature, payload or signer name: `Success` is false and
`Message` says why. ECDSA signatures are expected in ASN.1 DER form, as WebAuthn delivers them.

## Comparing keys

Two PEM strings can encode the same key differently (a named curve OID versus explicit curve
parameters, for example). Compare the parsed key material, not the PEM text.

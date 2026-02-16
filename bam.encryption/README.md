# bam.encryption

A comprehensive cryptographic library providing AES symmetric encryption, RSA asymmetric encryption, ECC key agreement, HMAC computation, digital signatures, X.509 certificate issuance, and encrypted dictionary collections.

## Overview

bam.encryption implements the cryptographic layer of the BAM framework. It supports two primary encryption modes: **symmetric** (AES-256 with PKCS7 padding) and **asymmetric** (RSA via BouncyCastle). The library is organized around clean interfaces (`IEncryptor`/`IDecryptor` for operations, `IAesKeySource`/`IRsaKeySource` for key provisioning) that allow storage and protocol layers to depend on abstractions rather than concrete crypto implementations.

The library provides a transformer pipeline architecture (`ValueTransformerPipeline<T>`) that chains byte-level and base64-level transformations. For example, `AesByteTransformer` handles raw byte encryption while `AesBase64Transformer` adds base64 encoding on top. The same pattern applies to RSA via `RsaByteTransformer` and `RsaBase64Transformer`. Higher-level encryptors like `SymmetricDataEncryptor<T>` and `RsaAsymmetricDataEncryptor<T>` serialize objects to JSON, encrypt the bytes, and produce typed `Cipher<T>` objects that carry type metadata alongside the encrypted payload.

Beyond encryption, the library provides ECC key agreement (Elliptic Curve Diffie-Hellman via BouncyCastle) for deriving shared AES keys, HMAC-SHA256/SHA1 computation (including double-HMAC for key derivation), RSA digital signature creation and verification, and X.509 certificate generation. Utility classes like `EncryptedDictionary` and `DecryptedDictionary` provide dictionary-like collections where all keys and values are transparently encrypted or decrypted. The `DisposablePem` base class ensures that private key material in PEM byte arrays is zeroed on disposal.

## Key Classes

| Class | Description |
|-------|-------------|
| `AesKey` | Holds an AES key and IV pair. Provides `Encrypt`/`Decrypt` for strings and `EncryptBytes`/`DecryptBytes` for byte arrays. Implements `IAesKeySource`. |
| `Aes` | Static utility class with AES encrypt/decrypt methods for strings, bytes, and object serialization. Supports password-based key derivation. |
| `AesEncryptor` | `IEncryptor` implementation backed by an `AesKey`. Encrypts strings and byte arrays. |
| `AesDecryptor` | `IDecryptor` implementation backed by an `AesKey`. Decrypts strings, byte arrays, and `Cipher` objects. |
| `AesByteTransformer` | Byte-level AES transformer with a reverse transformer for decryption. Part of the pipeline architecture. |
| `AesBase64Transformer` | String-level AES transformer that produces/consumes base64-encoded ciphers. |
| `RsaPublicPrivateKeyPair` | Wraps a BouncyCastle `AsymmetricCipherKeyPair` for RSA. Provides encrypt/decrypt via public/private keys. |
| `RsaByteTransformer` | Byte-level RSA transformer using the public key for encryption and private key for decryption. |
| `RsaBase64Transformer` | String-level RSA transformer producing/consuming base64-encoded ciphers. |
| `RsaPublicKey` | Wraps an RSA public key PEM string. Provides `Encrypt` and `EncryptBytes` methods. |
| `RsaKeyPair` | Wrapper around `RsaPublicPrivateKeyPair` implementing `IKeyPair`. Manages PEM serialization and public/private key separation. |
| `EccPublicPrivateKeyPair` | Elliptic Curve key pair supporting ECDH key agreement to derive shared `AesKey` instances. |
| `EccKeyPair` | Wraps `EccPublicPrivateKeyPair` with convenience methods for self-AES keys and shared AES keys. |
| `Hmac` | Static class for HMAC-SHA256, HMAC-SHA1, and double-HMAC computations. |
| `HmacKeyProvider` | `IHmacKeyProvider` implementation that generates, caches, and persists named HMAC keys to the BAM vault directory. |
| `SymmetricDataEncryptor<T>` | Generic encryptor that serializes objects of type `T` to JSON, AES-encrypts the bytes, and returns `Cipher<T>`. |
| `SymmetricDataDecryptor<T>` | Counterpart to `SymmetricDataEncryptor<T>` that decrypts `Cipher<T>` back to typed objects. |
| `RsaAsymmetricDataEncryptor<T>` | Generic encryptor using RSA public key encryption on serialized object data. |
| `RsaAsymmetricDataDecryptor<T>` | Counterpart decryptor using RSA private key decryption. |
| `Cipher` / `Cipher<T>` | Typed wrapper around encrypted byte data with implicit conversions to/from `byte[]` and `string` (base64). |
| `ContentCipher` | Abstract base for ciphers that carry a `ContentType` media type string. |
| `SymmetricContentCipher` | Content cipher tagged with `MediaTypes.SymmetricCipher`. |
| `RsaAsymmetricContentCipher` | Content cipher tagged with `MediaTypes.AsymmetricCipher`. |
| `Encrypted` | Salted AES cipher with auto-generated key/IV. Implicit string conversion returns base64 cipher. |
| `Decrypted` | Counterpart to `Encrypted` that decrypts and strips salt. |
| `EncryptedDictionary` | `IEncryptedDictionary` implementation where keys and values are transparently AES-encrypted on write. |
| `DecryptedDictionary` | `IDecryptedDictionary` implementation that transparently decrypts keys and values on read. |
| `Signature` | `ISignature` implementation holding signature bytes, algorithm name, and original data. |
| `SignatureVerification` | `ISignatureVerification` result with success flag, message, and issuer public key. |
| `RsaSignatureProvider` | Signs data using RSA private keys (default algorithm: SHA512WITHRSA). |
| `CertificateIssuer` | Abstract X.509 certificate generator supporting both RSA and ECC issuer keys. Uses BouncyCastle's `X509V3CertificateGenerator`. |
| `Pem` | Static utility class for PEM encoding/decoding of BouncyCastle key objects. |
| `DisposablePem` | Base class that zeroes PEM byte arrays on disposal for secure key lifecycle management. |
| `ProtectedKeyUsageContext` | Abstract disposable context for controlled private key access. |
| `EncryptAttribute` | Attribute to mark classes requiring encryption when streamed to file or network. |
| `Secure` | Static utility for generating cryptographically secure random strings. |
| `Extensions` | Extension methods for RSA key pair generation, public key encryption, and private key decryption on strings and byte arrays. |

## Dependencies

**Project References:**
- `bam.base` -- core framework utilities (serialization, hashing, argument validation, extension methods)
- `bam.base.transformers` -- `ValueTransformerPipeline<T>`, `ValueReverseTransformerPipeline<T>`, and related transformer infrastructure

**Package References:**
- `BouncyCastle.Cryptography` (2.6.2) -- RSA engine, ECC key generation, PEM reader/writer, X.509 certificate generation, secure random number generation

## Usage Examples

### AES symmetric encryption

```csharp
using Bam.Encryption;

// Generate a new AES key
AesKey key = new AesKey();

// Encrypt and decrypt a string
string cipher = key.Encrypt("secret message");
string plaintext = key.Decrypt(cipher);

// Encrypt and decrypt bytes
byte[] encrypted = key.EncryptBytes(data);
byte[] decrypted = key.DecryptBytes(encrypted);
```

### Password-based AES encryption

```csharp
using Bam.Encryption;

string cipher = Aes.Encrypt("my data", "my-password");
string decrypted = Aes.Decrypt(cipher, "my-password");
```

### RSA asymmetric encryption

```csharp
using Bam.Encryption;

// Generate a new RSA key pair
var keyPair = new RsaPublicPrivateKeyPair();

// Encrypt with public key
string cipher = "plaintext".EncryptWithPublicKey(keyPair.AsymmetricCipherKeyPair);

// Decrypt with private key
string decrypted = cipher.DecryptWithPrivateKey(keyPair.AsymmetricCipherKeyPair);
```

### Typed object encryption with SymmetricDataEncryptor

```csharp
using Bam.Encryption;

var encryptor = new SymmetricDataEncryptor<MyClass>(new AesKey());
Cipher<MyClass> cipher = encryptor.Encrypt(myObject);

IDecryptor<MyClass> decryptor = encryptor.GetDecryptor();
MyClass restored = decryptor.DecryptCipher(cipher);
```

### ECC key agreement for shared AES keys

```csharp
using Bam.Encryption;

var alice = new EccPublicPrivateKeyPair();
var bob = new EccPublicPrivateKeyPair();

// Both derive the same shared AES key
AesKey aliceKey = alice.GetSharedAesKey(bob.PublicKeyPem);
AesKey bobKey = bob.GetSharedAesKey(alice.PublicKeyPem);

// Alice encrypts, Bob decrypts
string cipher = aliceKey.Encrypt("hello");
string plaintext = bobKey.Decrypt(cipher); // "hello"
```

### HMAC computation

```csharp
using Bam.Encryption;

byte[] hmac = Hmac.Sha256("message", "secret-key");
byte[] doubleHmac = Hmac.DoubleSha256("message", "secret-key");
```

### Digital signatures

```csharp
using Bam.Encryption;

var signatureProvider = new RsaSignatureProvider();
var keySource = /* IRsaKeySource implementation */;

ISignature signature = signatureProvider.Sign(keySource, "data to sign");
ISignatureVerification verification = signatureProvider.VerifySignature(
    signature, keySource.GetRsaPublicKey());
```

## Known Gaps / Not Yet Implemented

- `IApplicationKeySet` and `ICommunicationKeySet` are defined as interfaces but have no implementations in this project.
- `ProtectedKeyUsageContext` is an abstract class with no concrete implementations.
- The `Extensions.EcKeyPair()` method is commented out, suggesting ECC key pair generation via BouncyCastle's `ECKeyPairGenerator` was planned but not completed.
- `XmlBase64Aeskey` and its `SystemKey` property are marked `[Obsolete]` in favor of `AesKey.SystemKey`, but are still referenced by the `Aes` static class for default encrypt/decrypt operations.
- Several files are excluded from compilation in the .csproj (`CertificateIssuerOptions.cs`, vault-related files), indicating in-progress features.

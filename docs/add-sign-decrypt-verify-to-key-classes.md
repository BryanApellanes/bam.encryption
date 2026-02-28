# Plan: Add Sign/Decrypt/Verify to PrivateKey/PublicKey + EccPrivateKeyUsageContext

## Context

The `PrivateKey` and `PublicKey` abstract classes currently have no `Sign` or `Verify` methods, even though signing/verification infrastructure already exists in `SignatureProvider`, `RsaSignatureProvider`, and `EccSignatureProvider`. This forces callers to wire up `PrivateKeyProvider` + `SignatureProvider` manually. Similarly, `RsaPrivateKey` has no `Decrypt` method despite `RsaPublicPrivateKeyPair.Decrypt` existing. There is also no `EccPrivateKeyUsageContext` counterpart to `RsaPrivateKeyUsageContext`. This plan adds these capabilities by delegating to existing infrastructure.

## Existing Infrastructure Being Reused

| Component | File | Role |
|-----------|------|------|
| `SignatureProvider.Sign` | `bam.encryption/SignatureProvider.cs` | BouncyCastle signer logic — takes `IPrivateKeyProvider`, returns `ISignature` |
| `SignatureProvider.VerifySignature` | `bam.encryption/SignatureProvider.cs` | BouncyCastle verifier logic — takes `ISignature` + `IPublicKey` |
| `PrivateKeyProvider` | `bam.encryption/PrivateKeyProvider.cs` | Wraps `AsymmetricKeyParameter` as `IPrivateKeyProvider` |
| `RsaPublicPrivateKeyPair.Decrypt` | `bam.encryption/RsaPublicPrivateKeyPair.cs` | Existing RSA decryption (string→string, byte[]→byte[]) |
| `RsaPrivateKeyUsageContext` | `bam.encryption/RsaPrivateKeyUsageContext.cs` | Pattern template for ECC context: AES-encrypt PEM in ctor, decrypt in UseKey |
| `ISignature` / `Signature` | `bam.encryption/ISignature.cs`, `Signature.cs` | Return type for signing operations |
| `ISignatureVerification` / `SignatureVerification` | `bam.encryption/ISignatureVerification.cs` | Return type for verification operations |
| `EccPublicPrivateKeyPair` | `bam.encryption/EccPublicPrivateKeyPair.cs` | ECC key pair with `AsymmetricCipherKeyPair` and PEM byte handling |

## Alternative Considered

**Inject `ISignatureProvider` into `PrivateKey`/`PublicKey`?** This would make `PrivateKey` depend on a service, but `PrivateKey` is a value-like wrapper around `AsymmetricKeyParameter` — not a service. Adding a dependency would violate SRP. Instead, `Sign`/`Verify` are convenience methods that internally instantiate a `PrivateKeyProvider` and call `SignatureProvider.Sign`/`VerifySignature` statically. This keeps `PrivateKey`/`PublicKey` as self-contained key representations while reusing the signing infrastructure. The subclasses (`RsaPrivateKey`, `EccPrivateKey`) override only to provide algorithm-appropriate defaults.

---

## Step 1: Add `Sign` to `PrivateKey` abstract class and `IPrivateKey` interface

**Files**: `bam.encryption/PrivateKey.cs`, `bam.encryption/IPrivateKey.cs`

Add abstract `Sign` methods to `PrivateKey` and corresponding interface methods to `IPrivateKey`. Each subclass provides its algorithm default.

```csharp
// IPrivateKey
ISignature Sign(string data);
ISignature Sign(byte[] data);

// PrivateKey
public abstract ISignature Sign(string data);
public abstract ISignature Sign(byte[] data);
```

The `byte[]` overload converts to Base64 string and delegates to the `string` overload — since `SignatureProvider.Sign` works with strings and stores the original data in `ISignature.Data`.

## Step 2: Implement `Sign` in `RsaPrivateKey`

**File**: `bam.encryption/RsaPrivateKey.cs`

```csharp
public override ISignature Sign(string data)
{
    return new RsaSignatureProvider().Sign(new PrivateKeyProvider(Value), data, "SHA512WITHRSA");
}

public override ISignature Sign(byte[] data)
{
    return Sign(Convert.ToBase64String(data));
}
```

Reuses: `RsaSignatureProvider` (delegates to `SignatureProvider.Sign`), `PrivateKeyProvider(AsymmetricKeyParameter)`.

## Step 3: Add `Decrypt` to `RsaPrivateKey`

**File**: `bam.encryption/RsaPrivateKey.cs`

```csharp
public string Decrypt(string base64Cipher, Encoding? encoding = null)
{
    using RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair(Pem);
    return keyPair.Decrypt(base64Cipher, encoding);
}

public byte[] Decrypt(byte[] cipherBytes)
{
    using RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair(Pem);
    return keyPair.Decrypt(cipherBytes);
}
```

Reuses: `RsaPublicPrivateKeyPair.Decrypt` — the existing decryption implementation.

## Step 4: Implement `Sign` in `EccPrivateKey`

**File**: `bam.encryption/EccPrivateKey.cs`

```csharp
public override ISignature Sign(string data)
{
    return new EccSignatureProvider().Sign(new PrivateKeyProvider(Value), data, "SHA256WITHECDSA");
}

public override ISignature Sign(byte[] data)
{
    return Sign(Convert.ToBase64String(data));
}
```

Reuses: `EccSignatureProvider` (delegates to `SignatureProvider.Sign`), `PrivateKeyProvider(AsymmetricKeyParameter)`.

## Step 5: Add `Verify` to `PublicKey` abstract class

**File**: `bam.encryption/PublicKey.cs`

```csharp
public ISignatureVerification Verify(ISignature signature)
{
    return new RsaSignatureProvider().VerifySignature(signature, this);
}
```

`VerifySignature` lives on the base `SignatureProvider` class and is algorithm-agnostic (it reads the algorithm from `ISignature.Algorithm` and uses BouncyCastle's `SignerUtilities.GetSigner`). So `RsaSignatureProvider` vs `EccSignatureProvider` doesn't matter for verification — both inherit the same `VerifySignature` from `SignatureProvider`. A single non-virtual method on `PublicKey` is sufficient.

## Step 6–7: `RsaPublicKey` and `EccPublicKey` inherit `Verify` automatically

No changes needed — both inherit from `PublicKey`.

## Step 8: Add `SignWithKey` to `RsaPrivateKeyUsageContext`

**File**: `bam.encryption/RsaPrivateKeyUsageContext.cs`

```csharp
public ISignature SignWithKey(string data)
{
    ISignature? result = null;
    UseKey(privateKey => result = privateKey.Sign(data));
    return result!;
}

public ISignature SignWithKey(byte[] data)
{
    ISignature? result = null;
    UseKey(privateKey => result = privateKey.Sign(data));
    return result!;
}
```

Reuses: `UseKey` (existing AES-decrypt-in-scope pattern), `PrivateKey.Sign` (from Step 2).

## Step 9: Create `EccPrivateKeyUsageContext`

**New file**: `bam.encryption/EccPrivateKeyUsageContext.cs`

Follows the exact same pattern as `RsaPrivateKeyUsageContext`: AES-encrypt PEM bytes in constructor, AES-decrypt in `UseKey`, clear on dispose. Includes `SignWithKey` overloads.

## Step 10: Create `EccProtectedKeyUsageContextFactory`

**New file**: `bam.encryption/EccProtectedKeyUsageContextFactory.cs`

Mirrors `RsaProtectedKeyUsageContextFactory` — implements `IProtectedKeyUsageContextFactory` and returns `EccPrivateKeyUsageContext`.

## Step 11: Update existing test

**File**: `bam.storage.tests/Integration/RsaPrivateKeyOpaqueStorageShould.cs`

Updated `UseNamedKeyExecutesActionWithLoadedKey` to use `((RsaPrivateKey)privateKey).Decrypt(encrypted)` instead of creating a new `RsaPublicPrivateKeyPair` to decrypt.

## Step 12: New test files

- `bam.encryption.tests/Unit/RsaPrivateKeyShould.cs` — 4 tests (sign/verify string, sign/verify bytes, decrypt string, decrypt bytes)
- `bam.encryption.tests/Unit/EccPrivateKeyShould.cs` — 2 tests (sign/verify string, sign/verify bytes)
- `bam.encryption.tests/Unit/RsaPrivateKeyUsageContextShould.cs` — 3 tests (sign string, sign bytes, use key decrypt)
- `bam.encryption.tests/Unit/EccPrivateKeyUsageContextShould.cs` — 4 tests (use key, sign string, sign bytes, dispose)

---

## Files Summary

| File | Action | Project |
|------|--------|---------|
| `bam.encryption/IPrivateKey.cs` | Modify — add `Sign` methods to interface | bam.encryption |
| `bam.encryption/PrivateKey.cs` | Modify — add abstract `Sign` methods | bam.encryption |
| `bam.encryption/RsaPrivateKey.cs` | Modify — implement `Sign`, add `Decrypt` | bam.encryption |
| `bam.encryption/EccPrivateKey.cs` | Modify — implement `Sign` | bam.encryption |
| `bam.encryption/PublicKey.cs` | Modify — add `Verify` method | bam.encryption |
| `bam.encryption/RsaPrivateKeyUsageContext.cs` | Modify — add `SignWithKey` overloads | bam.encryption |
| `bam.encryption/EccPrivateKeyUsageContext.cs` | Create | bam.encryption |
| `bam.encryption/EccProtectedKeyUsageContextFactory.cs` | Create | bam.encryption |
| `bam.encryption.tests/Unit/RsaPrivateKeyShould.cs` | Create | bam.encryption.tests |
| `bam.encryption.tests/Unit/EccPrivateKeyShould.cs` | Create | bam.encryption.tests |
| `bam.encryption.tests/Unit/RsaPrivateKeyUsageContextShould.cs` | Create | bam.encryption.tests |
| `bam.encryption.tests/Unit/EccPrivateKeyUsageContextShould.cs` | Create | bam.encryption.tests |
| `bam.storage.tests/.../RsaPrivateKeyOpaqueStorageShould.cs` | Modify — use `RsaPrivateKey.Decrypt` | bam.storage.tests |

## Verification

All tests pass: 28/28 bam.encryption tests, 15/15 bam.storage tests.

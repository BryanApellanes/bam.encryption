# bam.encryption.tests

Unit tests for the bam.encryption library, validating AES and RSA encryption round-trips, transformer pipelines, ECC key agreement, and typed object encryption/decryption.

## Overview

bam.encryption.tests is a console-based test project that uses the bam.test framework's menu-driven test runner (`BamConsoleContext.StaticMain`). It contains three test classes covering the primary encryption subsystems: AES/RSA transformers and encryptor/decryptor pairs (`EncryptionTransformersShould`), symmetric data encryption focused tests (`SymmetricDataEncryptorShould`), and ECC shared key agreement (`EccPublicPrivateKeyPairShould`).

The tests exercise multiple layers of the encryption API: low-level byte transformers (`AesByteTransformer`, `RsaByteTransformer`), base64-level transformers (`AesBase64Transformer`, `RsaBase64Transformer`), high-level typed encryptors (`SymmetricDataEncryptor<T>`, `RsaAsymmetricDataEncryptor<T>`), and the `ValueTransformerPipelineFactory` for dynamically constructed pipelines. Each test verifies that data survives a complete encrypt-decrypt round-trip with exact fidelity.

The ECC tests verify that two independent ECC key pairs can derive the same shared AES key via Elliptic Curve Diffie-Hellman, and that a single key pair generates a consistent self-shared key. These tests confirm cross-party encryption compatibility by encrypting with one derived key and decrypting with the other.

## Key Classes

| Class | Description |
|-------|-------------|
| `Program` | Entry point that delegates to `BamConsoleContext.StaticMain` for menu-driven test execution. |
| `EncryptionTransformersShould` | Comprehensive test class covering: `AesKey` encrypt/decrypt, `AesByteTransformer` round-trip, `AesBase64Transformer` round-trip, `RsaByteTransformer` round-trip, `RsaBase64Transformer` round-trip, `SymmetricDataEncryptor<T>` for objects/strings/bytes, `RsaAsymmetricDataEncryptor<T>` for strings/bytes, and `ValueTransformerPipelineFactory`. |
| `SymmetricDataEncryptorShould` | Focused tests for `SymmetricDataEncryptor<object>` verifying text and byte encryption/decryption round-trips with 1000-character payloads. |
| `EccPublicPrivateKeyPairShould` | Tests ECC Diffie-Hellman key agreement: verifies two independent ECC pairs derive identical shared AES keys, and a single pair's self-shared key is consistent. |
| `TestMonkey` | Simple POCO test fixture with `Name` (string) and `TailCount` (int) properties, used for typed encryption tests. |

## Dependencies

**Project References:**
- `bam.test` -- test framework providing `UnitTestMenuContainer`, `[UnitTestMenu]`, `[UnitTest]`, and `When.A<T>()` fluent API
- `bam.console` -- console infrastructure for `BamConsoleContext.StaticMain`
- `bam.encryption` -- the encryption library under test

**Package References:**
- None

## Usage Examples

### Running all tests

```bash
dotnet run --project submodules/bam.encryption/bam.encryption.tests/bam.encryption.tests.csproj -- --ut
```

Note: Use `--ut` (not `/ut`) when running from Git Bash, as Git Bash rewrites `/ut` to a filesystem path.

### Running from the interactive menu

```bash
dotnet run --project submodules/bam.encryption/bam.encryption.tests/bam.encryption.tests.csproj
```

This launches the menu-driven test runner. Test classes can be selected by their selector shortcuts:
- `sgs` -- EncryptionTransformersShould
- `sdes` -- SymmetricDataEncryptorShould
- `eppkps` -- EccPublicPrivateKeyPairShould

### Test structure example

```csharp
[UnitTestMenu("EncryptionTransformers Should", Selector = "sgs")]
public class EncryptionTransformersShould : UnitTestMenuContainer
{
    [UnitTest]
    public void AesKeyVectorPairTest()
    {
        string testData = "this is the test data";

        When.A<AesKey>("encrypts and decrypts with AES key",
            (aesKey) =>
            {
                string cipher = aesKey.Encrypt(testData);
                string deciphered = aesKey.Decrypt(cipher);
                return deciphered;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("deciphered equals original",
                testData.Equals((string)because.Result));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}
```

## Known Gaps / Not Yet Implemented

- No tests for HMAC computation (`Hmac` static class) or `HmacKeyProvider`.
- No tests for digital signatures (`RsaSignatureProvider`, `SignatureVerification`).
- No tests for `EncryptedDictionary` or `DecryptedDictionary`.
- No tests for `CertificateIssuer` (X.509 certificate generation).
- No tests for `Encrypted`/`Decrypted` salted cipher classes.
- No tests for PEM serialization/deserialization utilities.
- No negative/error-path tests (e.g., wrong key decryption, corrupted ciphertext, invalid PEM).

# Plan: Refactor bam.encryption.tests to use After.Setup

## Context

The test files in `bam.encryption.tests` use inline setup code (creating key pairs, private keys, public keys) before the `When.A<T>()` call. The `After.Setup` pattern from the bamtest framework provides a cleaner separation: register dependencies in a `TestCaseRegistry`, then resolve the test subject via `When<T>()` and access other registered objects via `reg.Get<T>()`.

Additionally, several existing tests still use `object[]` arrays for returning multiple values, which should be replaced with `ResultAs<T>()` per project convention.

## After.Setup Pattern

```csharp
// From bam.test/After.cs — returns TestCaseRegistry
After.Setup(reg => {
    reg.Set(new SomeObject());          // register by concrete type
    reg.For<IFoo>().Use(new Foo());     // register by interface
})
.When<T>("description", (obj, reg) => {
    var foo = reg.Get<IFoo>();          // retrieve from registry
    return obj.DoSomething(foo);
})
.TheTest
.ShouldPass(because => { ... })
.SoBeHappy()
.UnlessItFailed();
```

**Key API**: `TestCaseRegistry` extends `ServiceRegistry`. `When<T>` resolves `T` from the registry. The `(T obj, TestCaseRegistry reg)` overload gives access to both the subject and registry.

## Files Refactored

### 1. RsaPrivateKeyShould.cs — After.Setup (4 tests)

**File**: `bam.encryption.tests/Unit/RsaPrivateKeyShould.cs`

Moved key pair creation + derived key extraction into `After.Setup`. Uses `When<RsaPrivateKey>` to resolve the test subject and `reg.Get<RsaPublicKey>()` to access the public key.

### 2. EccPrivateKeyShould.cs — After.Setup (2 tests)

**File**: `bam.encryption.tests/Unit/EccPrivateKeyShould.cs`

Same approach: registered `EccPrivateKey` and `EccPublicKey` in setup.

### 3. RsaPrivateKeyUsageContextShould.cs — After.Setup (3 tests)

**File**: `bam.encryption.tests/Unit/RsaPrivateKeyUsageContextShould.cs`

Registered `RsaPublicKey` and `RsaPrivateKeyUsageContext` in setup. For the `UseKeyDecryptsAndExecutesAction` test, the encrypted string is also registered in setup since it depends on the key pair created there.

### 4. EccPrivateKeyUsageContextShould.cs — After.Setup (4 tests)

**File**: `bam.encryption.tests/Unit/EccPrivateKeyUsageContextShould.cs`

Kept `GetEccPemBytes` helper (needed because `EccPublicPrivateKeyPair.Pem` is `protected internal`). Registered `EccPublicKey` and `EccPrivateKeyUsageContext` in setup.

### 5. EccPublicPrivateKeyPairShould.cs — Fix object[] only

**File**: `bam.encryption.tests/Unit/EccPublicPrivateKeyPairShould.cs`

`After.Setup` was **not appropriate** here — tests need two instances of `EccPublicPrivateKeyPair` and the key pair IS the test subject. Replaced `object[]` return + unpacking with closure-captured variables and `ResultAs<string>()`.

### 6. EncryptionTransformersShould.cs — Fix object[] patterns + After.Setup

**File**: `bam.encryption.tests/Unit/EncryptionTransformersShould.cs`

- Fixed `object[]` in 4 tests (`TransformAes`, `TransformAesBase64`, `TransformRsaBytes`, `TransformRsaBase64`) using closure-captured variables
- Fixed raw casts `(string)because.Result` to `because.ResultAs<string>()` in 5 tests
- Refactored `ValueTransformerPipelineFactoryTest` to use `After.Setup` since it already creates a ServiceRegistry

### 7. SymmetricDataEncryptorShould.cs — Fix raw casts only

**File**: `bam.encryption.tests/Unit/SymmetricDataEncryptorShould.cs`

`After.Setup` was **not appropriate** — minimal setup, factory pattern is already clean. Fixed `(string)because.Result` to `because.ResultAs<string>()` in 2 tests.

## Files Summary

| File | After.Setup | Fix object[] | Fix raw casts |
|------|:-----------:|:------------:|:-------------:|
| `RsaPrivateKeyShould.cs` | Yes (4 tests) | n/a | n/a |
| `EccPrivateKeyShould.cs` | Yes (2 tests) | n/a | n/a |
| `RsaPrivateKeyUsageContextShould.cs` | Yes (3 tests) | n/a | n/a |
| `EccPrivateKeyUsageContextShould.cs` | Yes (4 tests) | n/a | n/a |
| `EccPublicPrivateKeyPairShould.cs` | No | Yes (2 tests) | n/a |
| `EncryptionTransformersShould.cs` | Yes (1 test) | Yes (4 tests) | Yes (5 tests) |
| `SymmetricDataEncryptorShould.cs` | No | No | Yes (2 tests) |

## Verification

```bash
cd C:/src/repos/bamtk/submodules/bam.encryption/bam.encryption.tests && dotnet build
MSYS_NO_PATHCONV=1 dotnet run -- /ut
# Result: 28 passed, 0 failed
```

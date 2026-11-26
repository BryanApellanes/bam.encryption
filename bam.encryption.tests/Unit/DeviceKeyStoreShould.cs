using System.Security.Cryptography;
using System.Text;
using Bam.Console;
using Bam.Encryption.DeviceKeys;
using Bam.Test;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Bam.Encryption.Tests.Unit;

/// <summary>
/// Pins the device-key contract (bam.encryption#24): the in-memory store's behaviour, the canonical key form and
/// fingerprint, the signed-payload format, and the Windows TPM store where a TPM is available.
/// </summary>
[UnitTestMenu("Device Key Store Should", Selector = "dks")]
public class DeviceKeyStoreShould : UnitTestMenuContainer
{
    private const string Scope = "alice.k7m2q9xz";

    [UnitTest]
    public void SignSoThatBouncyCastleVerifiesAndATamperedPayloadFails()
    {
        When.A<InMemoryDeviceKeyStore>("creates a key, signs a payload, and verifies it the way bam.protocol does",
            () => new InMemoryDeviceKeyStore(),
            (store) =>
            {
                DeviceKeyInfo info = store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult().Value!;
                byte[] payload = TaggedPayload.Build(TaggedPayload.DeviceKey, "alice", info.Fingerprint, "laptop", "2027-02-24T00:00:00Z").Value!;
                DeviceKeySignature signature = store.SignAsync(info.Id, payload).GetAwaiter().GetResult().Value!;
                byte[] tampered = (byte[])payload.Clone();
                tampered[tampered.Length - 1] ^= 1;
                return new SignOutcome(info, signature, Verify(info.PublicKeySpki, payload, signature.Der), Verify(info.PublicKeySpki, tampered, signature.Der));
            })
        .TheTest
        .ShouldPass<SignOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("the key is reported as software-protected", outcome.Info.Protection == DeviceKeyProtection.Software);
            because.ItsTrue("the alias was generated", outcome.Info.Id.Alias.Length == 16 && DeviceKeyId.IsValidName(outcome.Info.Id.Alias));
            because.ItsTrue("the fingerprint is 64 lowercase hex characters", IsLowerHex64(outcome.Info.Fingerprint));
            because.ItsTrue("the signature algorithm is the one bam.protocol verifies", outcome.Signature.Algorithm == "SHA256WITHECDSA");
            because.ItsTrue("the DER signature verifies with BouncyCastle", outcome.Verified);
            because.ItsTrue("a tampered payload does not verify", !outcome.TamperedVerified);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void GiveEveryEncodingOfAKeyTheFingerprintBamProtocolComputes()
    {
        When.A<string>("encodes one P-256 key three ways and fingerprints each",
            "P-256",
            (_) =>
            {
                using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                byte[] named = key.ExportSubjectPublicKeyInfo();
                ECPublicKeyParameters parameters = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(named);
                X9ECParameters curve = ECNamedCurveTable.GetByName("P-256");
                byte[] explicitForm = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                    new ECPublicKeyParameters("EC", parameters.Q, new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed()))).GetDerEncoded();
                byte[] compressed = new SubjectPublicKeyInfo(
                    new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, new DerObjectIdentifier(DeviceKeyAlgorithm.CurveOid)),
                    parameters.Q.GetEncoded(true)).GetDerEncoded();
                string bouncyCastle = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                    new ECPublicKeyParameters("EC", parameters.Q, new DerObjectIdentifier(DeviceKeyAlgorithm.CurveOid))).GetDerEncoded().Sha256();
                return new FingerprintOutcome(
                    CanonicalSpki.FingerprintOf(named).Value,
                    CanonicalSpki.FingerprintOf(explicitForm).Value,
                    CanonicalSpki.FingerprintOf(compressed).Value,
                    bouncyCastle,
                    named.SequenceEqual(CanonicalSpki.Canonicalize(compressed).Value!));
            })
        .TheTest
        .ShouldPass<FingerprintOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("the named form matches bam.protocol's hash of the named-curve SPKI", outcome.Named == outcome.BouncyCastle);
            because.ItsTrue("the explicit-parameters form gets the same fingerprint", outcome.Explicit == outcome.Named);
            because.ItsTrue("the compressed-point form gets the same fingerprint", outcome.Compressed == outcome.Named);
            because.ItsTrue("canonicalising the compressed form gives .NET's named-curve DER", outcome.CanonicalMatchesDotNet);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseKeysThatAreNotP256()
    {
        When.A<string>("canonicalises a P-384 key, an RSA key and garbage",
            "not P-256",
            (_) =>
            {
                using ECDsa p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
                using RSA rsa = RSA.Create(2048);
                return new RefusalOutcome(
                    CanonicalSpki.Canonicalize(p384.ExportSubjectPublicKeyInfo()).Error?.Category,
                    CanonicalSpki.Canonicalize(rsa.ExportSubjectPublicKeyInfo()).Error?.Category,
                    CanonicalSpki.Canonicalize(new byte[] { 1, 2, 3 }).Error?.Category,
                    CanonicalSpki.Canonicalize(Array.Empty<byte>()).Error?.Category);
            })
        .TheTest
        .ShouldPass<RefusalOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("P-384 is refused", outcome.P384 == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("RSA is refused", outcome.Rsa == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("garbage is refused, not thrown", outcome.Garbage == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("an empty key is refused", outcome.Empty == DeviceKeyErrorCategory.InvalidRequest);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReportEveryRefusalAsItsCategory()
    {
        When.A<InMemoryDeviceKeyStore>("makes each kind of bad request",
            () => new InMemoryDeviceKeyStore(),
            (store) =>
            {
                DeviceKeyId id = store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, Alias = "laptop", MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult().Value!.Id;
                using CancellationTokenSource cancelled = new CancellationTokenSource();
                cancelled.Cancel();
                DeviceKeyErrorCategory? biometry = store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, Access = DeviceKeyAccess.Biometry, MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult().Error?.Category;
                DeviceKeyErrorCategory? duplicate = store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, Alias = "laptop", MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult().Error?.Category;
                DeviceKeyErrorCategory? defaultMinimum = store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope }).GetAwaiter().GetResult().Error?.Category;
                DeviceKeyErrorCategory? strongBox = store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, MinimumProtection = DeviceKeyProtection.StrongBox }).GetAwaiter().GetResult().Error?.Category;
                DeviceKeyErrorCategory? badScope = store.CreateAsync(new DeviceKeyCreateRequest { Scope = "../etc", MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult().Error?.Category;
                DeviceKeyErrorCategory? emptyData = store.SignAsync(id, Array.Empty<byte>()).GetAwaiter().GetResult().Error?.Category;
                DeviceKeyErrorCategory? cancel = store.SignAsync(id, new byte[] { 1 }, null, cancelled.Token).GetAwaiter().GetResult().Error?.Category;
                bool firstDelete = store.DeleteAsync(id).GetAwaiter().GetResult().Value;
                DeviceKeyResult<bool> secondDelete = store.DeleteAsync(id).GetAwaiter().GetResult();
                DeviceKeyErrorCategory? afterDelete = store.SignAsync(id, new byte[] { 1 }).GetAwaiter().GetResult().Error?.Category;
                return new CategoryOutcome(biometry, defaultMinimum, strongBox, duplicate, badScope, emptyData, cancel, firstDelete, secondDelete.Succeeded && !secondDelete.Value, afterDelete);
            })
        .TheTest
        .ShouldPass<CategoryOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("an access policy the store cannot enforce is NotSupported", outcome.Biometry == DeviceKeyErrorCategory.NotSupported);
            because.ItsTrue("the default minimum (Hardware) is refused by a software store", outcome.DefaultMinimum == DeviceKeyErrorCategory.NotSupported);
            because.ItsTrue("a StrongBox minimum is refused too", outcome.StrongBox == DeviceKeyErrorCategory.NotSupported);
            because.ItsTrue("a reused alias is AlreadyExists", outcome.Duplicate == DeviceKeyErrorCategory.AlreadyExists);
            because.ItsTrue("a path-like scope is InvalidRequest", outcome.BadScope == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("signing nothing is InvalidRequest", outcome.EmptyData == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("a cancelled token is Cancelled", outcome.Cancel == DeviceKeyErrorCategory.Cancelled);
            because.ItsTrue("the first delete removes the key", outcome.FirstDelete);
            because.ItsTrue("deleting again succeeds and reports nothing removed", outcome.SecondDeleteIdempotent);
            because.ItsTrue("signing with a deleted key is KeyNotFound", outcome.AfterDelete == DeviceKeyErrorCategory.KeyNotFound);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ListOnlyTheKeysOfOneScopeOldestFirst()
    {
        When.A<InMemoryDeviceKeyStore>("creates keys in two scopes at different times",
            () => new InMemoryDeviceKeyStore(new SteppingClock()),
            (store) =>
            {
                store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, Alias = "second-made-first", MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult();
                store.CreateAsync(new DeviceKeyCreateRequest { Scope = "bob.aaaaaaaa", Alias = "other", MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult();
                store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, Alias = "a-made-later", MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult();
                return store.ListAsync(Scope).GetAwaiter().GetResult().Value!.Select(info => info.Id.Alias).ToList();
            })
        .TheTest
        .ShouldPass<List<string>>((because, _, aliases) =>
        {
            because.ItsTrue("only this scope's two keys are listed", aliases.Count == 2);
            because.ItsTrue("the oldest key comes first", aliases[0] == "second-made-first" && aliases[1] == "a-made-later");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void BuildPayloadsByteForByteAndRefuseAmbiguousOnes()
    {
        When.A<string>("builds a pairing payload and some bad ones",
            TaggedPayload.DevicePair,
            (tag) =>
            {
                byte[] payload = TaggedPayload.Build(tag, "alice", "ABCD-EFGH", "Bryan's laptop").Value!;
                return new PayloadOutcome(
                    Encoding.UTF8.GetString(payload),
                    TaggedPayload.Build(tag, "alice", "line\nbreak").Error?.Category,
                    TaggedPayload.Build(tag, "tab\there").Error?.Category,
                    TaggedPayload.Build(TaggedPayload.RequestProof, "x").Error?.Category,
                    TaggedPayload.Build("BAM-DEVICE-KEY-2", "x").Error?.Category,
                    TaggedPayload.ChallengeFor(payload) == Convert.ToBase64String(SHA256.HashData(payload)).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
            })
        .TheTest
        .ShouldPass<PayloadOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("the tag comes first, fields follow one per line, no trailing newline", outcome.Text == "BAM-DEVICE-PAIR-1\nalice\nABCD-EFGH\nBryan's laptop");
            because.ItsTrue("a newline in a field is refused", outcome.NewLine == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("any control character is refused", outcome.Tab == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("the request-proof tag cannot be built here", outcome.RequestProof == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("an unknown tag is refused", outcome.Unknown == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("the challenge is base64url of the payload's SHA-256", outcome.ChallengeMatches);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void KeepAKeyInTheTpmAndSignWithIt()
    {
        WindowsTpmDeviceKeyStore probe = new WindowsTpmDeviceKeyStore();
        DeviceKeyCapabilities capabilities = probe.GetCapabilitiesAsync().GetAwaiter().GetResult();
        Skip.Unless(capabilities.IsSupported, $"no usable TPM here: {capabilities.Reason}");

        When.A<WindowsTpmDeviceKeyStore>("creates a TPM key, signs, lists, and deletes it",
            () => new WindowsTpmDeviceKeyStore(new DirectoryInfo(Path.Combine(Path.GetTempPath(), "bam-devicekeys-" + Guid.NewGuid().ToString("N"))), TimeProvider.System),
            (store) =>
            {
                string scope = "test." + DeviceKeyId.NewAlias();
                DeviceKeyErrorCategory? strongBox = store.CreateAsync(new DeviceKeyCreateRequest { Scope = scope, Alias = "sb", MinimumProtection = DeviceKeyProtection.StrongBox }).GetAwaiter().GetResult().Error?.Category;
                DeviceKeyResult<DeviceKeyInfo> created = store.CreateAsync(new DeviceKeyCreateRequest { Scope = scope, Alias = "tpm", AttestationChallenge = new byte[] { 1, 2, 3 } }).GetAwaiter().GetResult();
                try
                {
                    DeviceKeyInfo info = created.Value!;
                    byte[] payload = TaggedPayload.Build(TaggedPayload.DeviceRenew, "alice", info.Fingerprint).Value!;
                    DeviceKeySignature signature = store.SignAsync(info.Id, payload).GetAwaiter().GetResult().Value!;
                    int listed = store.ListAsync(scope).GetAwaiter().GetResult().Value!.Count;
                    bool deleted = store.DeleteAsync(info.Id).GetAwaiter().GetResult().Value;
                    DeviceKeyErrorCategory? afterDelete = store.GetAsync(info.Id).GetAwaiter().GetResult().Error?.Category;
                    return new TpmOutcome(strongBox, info.Attestation == null, info.Protection, Verify(info.PublicKeySpki, payload, signature.Der), listed, deleted, afterDelete);
                }
                finally
                {
                    store.DeleteAsync(new DeviceKeyId(scope, "tpm")).GetAwaiter().GetResult();
                }
            })
        .TheTest
        .ShouldPass<TpmOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("a StrongBox minimum is refused by the TPM store", outcome.StrongBox == DeviceKeyErrorCategory.NotSupported);
            because.ItsTrue("the TPM store gives no attestation yet, even with a challenge", outcome.NoAttestation);
            because.ItsTrue("the key is reported as hardware-protected", outcome.Protection == DeviceKeyProtection.Hardware);
            because.ItsTrue("the TPM signature verifies with BouncyCastle", outcome.Verified);
            because.ItsTrue("the key is listed", outcome.Listed == 1);
            because.ItsTrue("delete removed it", outcome.Deleted);
            because.ItsTrue("it is gone afterwards", outcome.AfterDelete == DeviceKeyErrorCategory.KeyNotFound);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static bool Verify(byte[] spki, byte[] payload, byte[] der)
    {
        ISigner signer = SignerUtilities.GetSigner("SHA256WITHECDSA");
        signer.Init(false, PublicKeyFactory.CreateKey(spki));
        signer.BlockUpdate(payload, 0, payload.Length);
        return signer.VerifySignature(der);
    }

    private static bool IsLowerHex64(string value)
    {
        return value.Length == 64 && value.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }

    private sealed class SteppingClock : TimeProvider
    {
        private DateTimeOffset _now = new DateTimeOffset(2026, 11, 26, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow()
        {
            _now = _now.AddSeconds(1);
            return _now;
        }
    }

    private sealed record SignOutcome(DeviceKeyInfo Info, DeviceKeySignature Signature, bool Verified, bool TamperedVerified);

    private sealed record FingerprintOutcome(string? Named, string? Explicit, string? Compressed, string BouncyCastle, bool CanonicalMatchesDotNet);

    private sealed record RefusalOutcome(DeviceKeyErrorCategory? P384, DeviceKeyErrorCategory? Rsa, DeviceKeyErrorCategory? Garbage, DeviceKeyErrorCategory? Empty);

    private sealed record CategoryOutcome(DeviceKeyErrorCategory? Biometry, DeviceKeyErrorCategory? DefaultMinimum, DeviceKeyErrorCategory? StrongBox, DeviceKeyErrorCategory? Duplicate, DeviceKeyErrorCategory? BadScope, DeviceKeyErrorCategory? EmptyData, DeviceKeyErrorCategory? Cancel, bool FirstDelete, bool SecondDeleteIdempotent, DeviceKeyErrorCategory? AfterDelete);

    private sealed record PayloadOutcome(string Text, DeviceKeyErrorCategory? NewLine, DeviceKeyErrorCategory? Tab, DeviceKeyErrorCategory? RequestProof, DeviceKeyErrorCategory? Unknown, bool ChallengeMatches);

    private sealed record TpmOutcome(DeviceKeyErrorCategory? StrongBox, bool NoAttestation, DeviceKeyProtection Protection, bool Verified, int Listed, bool Deleted, DeviceKeyErrorCategory? AfterDelete);
}

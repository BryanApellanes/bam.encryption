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

        DirectoryInfo roundTripRecords = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "bam-devicekeys-" + Guid.NewGuid().ToString("N")));
        When.A<WindowsTpmDeviceKeyStore>("creates a TPM key, signs, lists, and deletes it",
            () => new WindowsTpmDeviceKeyStore(roundTripRecords, TimeProvider.System),
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
        DeleteQuietly(roundTripRecords);
    }

    [UnitTest]
    public void RefuseNamesThatTwoStoresCouldMapToOneFile()
    {
        When.A<string[]>("checks names that collide on disk or are Windows device names",
            new[] { "alice.", "alice\n", "alice..", "alice-", "nul", "nul.x", "con", "com1", "lpt9.k7", "aux", "-alice", "" },
            (refused) => new NameOutcome(
                refused.Where(DeviceKeyId.IsValidName).ToList(),
                new[] { "a", "a.b", "a..b", "alice.k7m2q9xz", "console", "nully", "com10", new string('a', 64) }.Where(name => !DeviceKeyId.IsValidName(name)).ToList(),
                DeviceKeyId.IsValidName(new string('a', 65))))
        .TheTest
        .ShouldPass<NameOutcome>((because, _, outcome) =>
        {
            because.ItsTrue($"a trailing dot or dash, a trailing newline and the device names are refused (accepted: {string.Join(",", outcome.WronglyAccepted)})", outcome.WronglyAccepted.Count == 0);
            because.ItsTrue($"ordinary names still pass (refused: {string.Join(",", outcome.WronglyRefused)})", outcome.WronglyRefused.Count == 0);
            because.ItsTrue("65 characters is too long", !outcome.SixtyFiveAccepted);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseEveryMangledKeyWithoutThrowing()
    {
        When.A<string>("mutates every byte of a valid P-256 key and canonicalises each result",
            "P-256",
            (_) =>
            {
                using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                byte[] valid = key.ExportSubjectPublicKeyInfo();
                string original = CanonicalSpki.FingerprintOf(valid).Value!;
                byte[] badPrefix = (byte[])valid.Clone();
                badPrefix[valid.Length - 65] = 0xB8;
                int thrown = 0;
                int wrongFingerprint = 0;
                for (int position = 0; position < valid.Length; position++)
                {
                    for (int value = 0; value < 256; value++)
                    {
                        if (value == valid[position])
                        {
                            continue;
                        }
                        byte[] mutated = (byte[])valid.Clone();
                        mutated[position] = (byte)value;
                        try
                        {
                            DeviceKeyResult<string> fingerprint = CanonicalSpki.FingerprintOf(mutated);
                            if (fingerprint.Succeeded && fingerprint.Value != original)
                            {
                                wrongFingerprint++;
                            }
                        }
                        catch (Exception)
                        {
                            thrown++;
                        }
                    }
                }
                return new MangledOutcome(CanonicalSpki.Canonicalize(badPrefix).Error?.Category, thrown, wrongFingerprint);
            })
        .TheTest
        .ShouldPass<MangledOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("a bad point prefix (0xB8) is InvalidRequest", outcome.BadPrefix == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue($"no mutation throws ({outcome.Thrown} did)", outcome.Thrown == 0);
            because.ItsTrue($"a mutation that is accepted is the same key ({outcome.WrongFingerprint} were not)", outcome.WrongFingerprint == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseAFieldThatIsNotValidText()
    {
        When.A<string>("builds payloads with lone surrogates and with a real surrogate pair",
            TaggedPayload.DeviceKey,
            (tag) => new SurrogateOutcome(
                TaggedPayload.Build(tag, "abc\uD800").Error?.Category,
                TaggedPayload.Build(tag, "\uDC00abc").Error?.Category,
                TaggedPayload.Build(tag, "\uD83D\uDE00 laptop").Succeeded,
                TaggedPayload.Tags is string[]))
        .TheTest
        .ShouldPass<SurrogateOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("a trailing high surrogate is InvalidRequest", outcome.LoneHigh == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("a leading low surrogate is InvalidRequest", outcome.LoneLow == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("an emoji (a valid pair) is accepted", outcome.PairAccepted);
            because.ItsTrue("the tag list cannot be cast back to an array and edited", !outcome.TagsAreArray);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void GetKeysAndRefuseOnceDisposed()
    {
        When.A<InMemoryDeviceKeyStore>("gets a key, makes undefined and invalid requests, then disposes the store",
            () => new InMemoryDeviceKeyStore(),
            (store) =>
            {
                DeviceKeyInfo created = store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, Alias = "phone", MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult().Value!;
                DeviceKeyInfo? got = store.GetAsync(created.Id).GetAwaiter().GetResult().Value;
                DeviceKeyErrorCategory? missing = store.GetAsync(new DeviceKeyId(Scope, "nothing")).GetAwaiter().GetResult().Error?.Category;
                DeviceKeyErrorCategory? undefinedAccess = store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, Access = (DeviceKeyAccess)99, MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult().Error?.Category;
                DeviceKeyErrorCategory? undefinedProtection = store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, MinimumProtection = (DeviceKeyProtection)99 }).GetAwaiter().GetResult().Error?.Category;
                DeviceKeyErrorCategory? badListScope = store.ListAsync("Not A Scope").GetAwaiter().GetResult().Error?.Category;
                store.Dispose();
                DeviceKeyCapabilities afterDispose = store.GetCapabilitiesAsync().GetAwaiter().GetResult();
                return new DisposedOutcome(
                    got != null && got.Fingerprint == created.Fingerprint && got.PublicKeySpki.SequenceEqual(created.PublicKeySpki),
                    missing, undefinedAccess, undefinedProtection, badListScope,
                    store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult().Error?.Category,
                    store.SignAsync(created.Id, new byte[] { 1 }).GetAwaiter().GetResult().Error?.Category,
                    store.GetAsync(created.Id).GetAwaiter().GetResult().Error?.Category,
                    store.ListAsync(Scope).GetAwaiter().GetResult().Error?.Category,
                    afterDispose.IsSupported);
            })
        .TheTest
        .ShouldPass<DisposedOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("GetAsync returns the key as created", outcome.GotSameKey);
            because.ItsTrue("an unknown alias is KeyNotFound", outcome.Missing == DeviceKeyErrorCategory.KeyNotFound);
            because.ItsTrue("an undefined access value is InvalidRequest", outcome.UndefinedAccess == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("an undefined protection value is InvalidRequest", outcome.UndefinedProtection == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("listing an invalid scope is InvalidRequest", outcome.BadListScope == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("create after dispose is NotSupported", outcome.CreateAfter == DeviceKeyErrorCategory.NotSupported);
            because.ItsTrue("sign after dispose is NotSupported", outcome.SignAfter == DeviceKeyErrorCategory.NotSupported);
            because.ItsTrue("get after dispose is NotSupported", outcome.GetAfter == DeviceKeyErrorCategory.NotSupported);
            because.ItsTrue("list after dispose is NotSupported", outcome.ListAfter == DeviceKeyErrorCategory.NotSupported);
            because.ItsTrue("capabilities say unsupported after dispose", !outcome.SupportedAfter);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void ReportBadTpmRecordsAsFailuresWithoutThrowingOrDeleting()
    {
        WindowsTpmDeviceKeyStore probe = new WindowsTpmDeviceKeyStore();
        DeviceKeyCapabilities capabilities = probe.GetCapabilitiesAsync().GetAwaiter().GetResult();
        Skip.Unless(capabilities.IsSupported, $"no usable TPM here: {capabilities.Reason}");

        DirectoryInfo records = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "bam-devicekeys-" + Guid.NewGuid().ToString("N")));
        When.A<WindowsTpmDeviceKeyStore>("damages TPM key records in each way and reads them back",
            () => new WindowsTpmDeviceKeyStore(records, TimeProvider.System),
            (store) =>
            {
                string scope = "test." + DeviceKeyId.NewAlias();
                string[] aliases = { "empty", "null", "biometry", "undefined", "missing", "nocreated", "gone" };
                try
                {
                    foreach (string alias in aliases)
                    {
                        store.CreateAsync(new DeviceKeyCreateRequest { Scope = scope, Alias = alias }).GetAwaiter().GetResult();
                    }
                    DeviceKeyErrorCategory? duplicate = store.CreateAsync(new DeviceKeyCreateRequest { Scope = scope, Alias = "empty" }).GetAwaiter().GetResult().Error?.Category;
                    string scopeDirectory = Path.Combine(records.FullName, scope);
                    File.WriteAllText(Path.Combine(scopeDirectory, "empty.json"), string.Empty);
                    File.WriteAllText(Path.Combine(scopeDirectory, "null.json"), "null");
                    File.WriteAllText(Path.Combine(scopeDirectory, "biometry.json"), "{\"CreatedUtc\":\"2026-11-26T00:00:00+00:00\",\"Access\":4}");
                    File.WriteAllText(Path.Combine(scopeDirectory, "undefined.json"), "{\"CreatedUtc\":\"2026-11-26T00:00:00+00:00\",\"Access\":99}");
                    File.Delete(Path.Combine(scopeDirectory, "missing.json"));
                    File.WriteAllText(Path.Combine(scopeDirectory, "nocreated.json"), "{\"Access\":0}");
                    using (CngKey gone = CngKey.Open("bam.devicekey." + scope + "+gone", new CngProvider(WindowsTpmDeviceKeyStore.ProviderName)))
                    {
                        gone.Delete();
                    }
                    List<DeviceKeyErrorCategory?> categories = new[] { "empty", "null", "biometry", "undefined", "missing", "nocreated" }
                        .Select(alias => store.GetAsync(new DeviceKeyId(scope, alias)).GetAwaiter().GetResult().Error?.Category).ToList();
                    DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>> listed = store.ListAsync(scope).GetAwaiter().GetResult();
                    bool goneRecordKept = File.Exists(Path.Combine(scopeDirectory, "gone.json"));
                    DeviceKeyErrorCategory? goneCategory = store.GetAsync(new DeviceKeyId(scope, "gone")).GetAwaiter().GetResult().Error?.Category;
                    DeviceKeyResult<bool> goneDeleted = store.DeleteAsync(new DeviceKeyId(scope, "gone")).GetAwaiter().GetResult();
                    return new BadRecordOutcome(duplicate, categories, listed.Succeeded, listed.Value?.Count ?? -1, goneRecordKept, goneCategory,
                        goneDeleted.Succeeded && !File.Exists(Path.Combine(scopeDirectory, "gone.json")),
                        Directory.GetFiles(scopeDirectory, "*.tmp").Length);
                }
                finally
                {
                    foreach (string alias in aliases)
                    {
                        store.DeleteAsync(new DeviceKeyId(scope, alias)).GetAwaiter().GetResult();
                    }
                }
            })
        .TheTest
        .ShouldPass<BadRecordOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("a reused alias is AlreadyExists", outcome.Duplicate == DeviceKeyErrorCategory.AlreadyExists);
            because.ItsTrue($"an empty, null, wrong-access, undefined-access or missing record is PlatformFailure ({string.Join(",", outcome.Categories)})", outcome.Categories.All(category => category == DeviceKeyErrorCategory.PlatformFailure));
            because.ItsTrue("listing still succeeds and lists none of the damaged keys", outcome.ListSucceeded && outcome.Listed == 0);
            because.ItsTrue("a read leaves a stale record in place", outcome.GoneRecordKept);
            because.ItsTrue("a key whose TPM key is gone is KeyNotFound", outcome.GoneCategory == DeviceKeyErrorCategory.KeyNotFound);
            because.ItsTrue("DeleteAsync removes the stale record", outcome.GoneDeleted);
            because.ItsTrue("no temporary record files are left behind", outcome.TemporaryFiles == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
        DeleteQuietly(records);
    }

    [UnitTest]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void KeepNoTpmKeyWhenItsRecordCannotBeWritten()
    {
        WindowsTpmDeviceKeyStore probe = new WindowsTpmDeviceKeyStore();
        DeviceKeyCapabilities capabilities = probe.GetCapabilitiesAsync().GetAwaiter().GetResult();
        Skip.Unless(capabilities.IsSupported, $"no usable TPM here: {capabilities.Reason}");

        DirectoryInfo records = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "bam-devicekeys-" + Guid.NewGuid().ToString("N")));
        When.A<WindowsTpmDeviceKeyStore>("creates a key where a file blocks the scope's record directory, then retries",
            () => new WindowsTpmDeviceKeyStore(records, TimeProvider.System),
            (store) =>
            {
                string scope = "test." + DeviceKeyId.NewAlias();
                records.Create();
                string blocker = Path.Combine(records.FullName, scope);
                File.WriteAllText(blocker, "not a directory");
                try
                {
                    DeviceKeyResult<DeviceKeyInfo> blocked = store.CreateAsync(new DeviceKeyCreateRequest { Scope = scope, Alias = "k1" }).GetAwaiter().GetResult();
                    bool keyLeft = CngKey.Exists("bam.devicekey." + scope + "+k1", new CngProvider(WindowsTpmDeviceKeyStore.ProviderName));
                    File.Delete(blocker);
                    DeviceKeyResult<DeviceKeyInfo> retried = store.CreateAsync(new DeviceKeyCreateRequest { Scope = scope, Alias = "k1" }).GetAwaiter().GetResult();
                    return new BlockedOutcome(blocked.Error?.Category, keyLeft, retried.Succeeded, store.ListAsync(scope).GetAwaiter().GetResult().Value?.Count ?? -1);
                }
                finally
                {
                    store.DeleteAsync(new DeviceKeyId(scope, "k1")).GetAwaiter().GetResult();
                }
            })
        .TheTest
        .ShouldPass<BlockedOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("an unwritable record is PlatformFailure, not an exception", outcome.Blocked == DeviceKeyErrorCategory.PlatformFailure);
            because.ItsTrue("the TPM key was removed again", !outcome.KeyLeft);
            because.ItsTrue("a retry succeeds instead of reporting AlreadyExists", outcome.RetrySucceeded);
            because.ItsTrue("the retried key is listed", outcome.Listed == 1);
        })
        .SoBeHappy()
        .UnlessItFailed();
        DeleteQuietly(records);
    }

    [UnitTest]
    public void RefuseOversizedAndDeeplyNestedKeysWithoutOverflowingTheStack()
    {
        When.A<string>("canonicalises a padded key and nested ASN.1 under and over the length limit",
            "P-256",
            (_) =>
            {
                using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                byte[] valid = key.ExportSubjectPublicKeyInfo();
                byte[] padded = new byte[CanonicalSpki.MaximumLength + 1];
                Array.Copy(valid, padded, valid.Length);
                return new NestedOutcome(
                    CanonicalSpki.Canonicalize(padded).Error?.Category,
                    CanonicalSpki.Canonicalize(Nested(20 * 1024)).Error?.Category,
                    CanonicalSpki.Canonicalize(Nested(CanonicalSpki.MaximumLength)).Error?.Category,
                    CanonicalSpki.FingerprintOf(Nested(16 * 1024)).Error?.Category);
            })
        .TheTest
        .ShouldPass<NestedOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("a key one byte over the limit is InvalidRequest", outcome.OverLimit == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("20 KB of nested sequences is InvalidRequest, and the process survives", outcome.DeepNested == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("nested input at the limit is InvalidRequest", outcome.AtLimitNested == DeviceKeyErrorCategory.InvalidRequest);
            because.ItsTrue("FingerprintOf refuses nested input too", outcome.FingerprintNested == DeviceKeyErrorCategory.InvalidRequest);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ReportASignRacingADeleteAsKeyNotFound()
    {
        When.A<InMemoryDeviceKeyStore>("signs on one thread while another deletes the key, many times",
            () => new InMemoryDeviceKeyStore(),
            (store) =>
            {
                int thrown = 0;
                int unexpected = 0;
                byte[] payload = new byte[] { 1, 2, 3 };
                for (int i = 0; i < 2000; i++)
                {
                    DeviceKeyId id = store.CreateAsync(new DeviceKeyCreateRequest { Scope = Scope, MinimumProtection = DeviceKeyProtection.Software }).GetAwaiter().GetResult().Value!.Id;
                    Task<DeviceKeyResult<DeviceKeySignature>> signing = Task.Run(() => store.SignAsync(id, payload));
                    store.DeleteAsync(id).GetAwaiter().GetResult();
                    try
                    {
                        DeviceKeyResult<DeviceKeySignature> signed = signing.GetAwaiter().GetResult();
                        if (!signed.Succeeded && signed.Error?.Category != DeviceKeyErrorCategory.KeyNotFound)
                        {
                            unexpected++;
                        }
                    }
                    catch (Exception)
                    {
                        thrown++;
                    }
                }
                return new RaceOutcome(thrown, unexpected);
            })
        .TheTest
        .ShouldPass<RaceOutcome>((because, _, outcome) =>
        {
            because.ItsTrue($"no sign throws ({outcome.Thrown} did)", outcome.Thrown == 0);
            because.ItsTrue($"a sign that loses the race is KeyNotFound ({outcome.Unexpected} were something else)", outcome.Unexpected == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void GiveOneKeyWhenTwoTpmStoresCreateTheSameId()
    {
        WindowsTpmDeviceKeyStore probe = new WindowsTpmDeviceKeyStore();
        DeviceKeyCapabilities capabilities = probe.GetCapabilitiesAsync().GetAwaiter().GetResult();
        Skip.Unless(capabilities.IsSupported, $"no usable TPM here: {capabilities.Reason}");

        DirectoryInfo records = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "bam-devicekeys-" + Guid.NewGuid().ToString("N")));
        When.A<WindowsTpmDeviceKeyStore>("starts two store instances on one record directory creating one id, several rounds",
            () => new WindowsTpmDeviceKeyStore(records, TimeProvider.System),
            (first) =>
            {
                WindowsTpmDeviceKeyStore second = new WindowsTpmDeviceKeyStore(records, TimeProvider.System);
                string scope = "test." + DeviceKeyId.NewAlias();
                List<string> problems = new List<string>();
                for (int round = 0; round < 4; round++)
                {
                    DeviceKeyId id = new DeviceKeyId(scope, "race" + round);
                    try
                    {
                        using Barrier barrier = new Barrier(2);
                        Task<DeviceKeyResult<DeviceKeyInfo>>[] creates = new[] { first, second }
                            .Select(store => Task.Run(() =>
                            {
                                barrier.SignalAndWait();
                                return store.CreateAsync(new DeviceKeyCreateRequest { Scope = scope, Alias = id.Alias }).GetAwaiter().GetResult();
                            }))
                            .ToArray();
                        Task.WaitAll(creates);
                        List<DeviceKeyResult<DeviceKeyInfo>> results = creates.Select(task => task.Result).ToList();
                        List<DeviceKeyResult<DeviceKeyInfo>> winners = results.Where(result => result.Succeeded).ToList();
                        if (winners.Count != 1 || results.Count(result => result.Error?.Category == DeviceKeyErrorCategory.AlreadyExists) != 1)
                        {
                            problems.Add($"round {round}: {string.Join(", ", results.Select(result => result.Succeeded ? "Success" : $"{result.Error?.Category} ({result.Error?.Message})"))}");
                            continue;
                        }
                        DeviceKeyResult<DeviceKeyInfo> got = first.GetAsync(id).GetAwaiter().GetResult();
                        DeviceKeyResult<DeviceKeySignature> signed = second.SignAsync(id, new byte[] { 1 }).GetAwaiter().GetResult();
                        if (!got.Succeeded || got.Value!.Fingerprint != winners[0].Value!.Fingerprint || !signed.Succeeded || !Verify(winners[0].Value!.PublicKeySpki, new byte[] { 1 }, signed.Value!.Der))
                        {
                            problems.Add($"round {round}: the winner's key is not the one in the TPM ({got.Error?.Category})");
                        }
                    }
                    finally
                    {
                        first.DeleteAsync(id).GetAwaiter().GetResult();
                    }
                }
                return problems;
            })
        .TheTest
        .ShouldPass<List<string>>((because, _, problems) =>
        {
            because.ItsTrue($"every round gives exactly one Success, one AlreadyExists, and the winner's key signs ({string.Join("; ", problems)})", problems.Count == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
        DeleteQuietly(records);
    }

    [UnitTest]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void NeverReportABusyTpmAsUnsupported()
    {
        WindowsTpmDeviceKeyStore probe = new WindowsTpmDeviceKeyStore();
        DeviceKeyCapabilities capabilities = probe.GetCapabilitiesAsync().GetAwaiter().GetResult();
        Skip.Unless(capabilities.IsSupported, $"no usable TPM here: {capabilities.Reason}");

        DirectoryInfo records = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "bam-devicekeys-" + Guid.NewGuid().ToString("N")));
        When.A<WindowsTpmDeviceKeyStore>("signs with one key from 8 threads, 6 times each, while asking for capabilities",
            () => new WindowsTpmDeviceKeyStore(records, TimeProvider.System),
            (store) =>
            {
                DeviceKeyInfo info = store.CreateAsync(new DeviceKeyCreateRequest { Scope = "test." + DeviceKeyId.NewAlias(), Alias = "busy" }).GetAwaiter().GetResult().Value!;
                try
                {
                    byte[] payload = TaggedPayload.Build(TaggedPayload.DeviceRenew, "alice", info.Fingerprint).Value!;
                    int notSupported = 0;
                    int thrown = 0;
                    int verified = 0;
                    Task[] threads = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
                    {
                        for (int i = 0; i < 6; i++)
                        {
                            try
                            {
                                DeviceKeyResult<DeviceKeySignature> signed = store.SignAsync(info.Id, payload).GetAwaiter().GetResult();
                                if (signed.Error?.Category == DeviceKeyErrorCategory.NotSupported || !store.GetCapabilitiesAsync().GetAwaiter().GetResult().IsSupported)
                                {
                                    Interlocked.Increment(ref notSupported);
                                }
                                if (signed.Succeeded && Verify(info.PublicKeySpki, payload, signed.Value!.Der))
                                {
                                    Interlocked.Increment(ref verified);
                                }
                            }
                            catch (Exception)
                            {
                                Interlocked.Increment(ref thrown);
                            }
                        }
                    })).ToArray();
                    Task.WaitAll(threads);
                    return new BusyOutcome(notSupported, thrown, verified);
                }
                finally
                {
                    store.DeleteAsync(info.Id).GetAwaiter().GetResult();
                }
            })
        .TheTest
        .ShouldPass<BusyOutcome>((because, _, outcome) =>
        {
            because.ItsTrue($"a busy TPM is never NotSupported ({outcome.NotSupported} were)", outcome.NotSupported == 0);
            because.ItsTrue($"nothing throws ({outcome.Thrown} did)", outcome.Thrown == 0);
            because.ItsTrue($"the signatures verify ({outcome.Verified} of 48)", outcome.Verified == 48);
        })
        .SoBeHappy()
        .UnlessItFailed();
        DeleteQuietly(records);
    }

    [UnitTest]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public void CreateAgainOverARecordWhoseTpmKeyIsGone()
    {
        WindowsTpmDeviceKeyStore probe = new WindowsTpmDeviceKeyStore();
        DeviceKeyCapabilities capabilities = probe.GetCapabilitiesAsync().GetAwaiter().GetResult();
        Skip.Unless(capabilities.IsSupported, $"no usable TPM here: {capabilities.Reason}");

        DirectoryInfo records = new DirectoryInfo(Path.Combine(Path.GetTempPath(), "bam-devicekeys-" + Guid.NewGuid().ToString("N")));
        When.A<WindowsTpmDeviceKeyStore>("creates a key, removes it from the TPM behind the store's back, and creates the same id again",
            () => new WindowsTpmDeviceKeyStore(records, TimeProvider.System),
            (store) =>
            {
                DeviceKeyId id = new DeviceKeyId("test." + DeviceKeyId.NewAlias(), "stale");
                try
                {
                    DeviceKeyInfo before = store.CreateAsync(new DeviceKeyCreateRequest { Scope = id.Scope, Alias = id.Alias }).GetAwaiter().GetResult().Value!;
                    using (CngKey gone = CngKey.Open("bam.devicekey." + id.Scope + "+" + id.Alias, new CngProvider(WindowsTpmDeviceKeyStore.ProviderName)))
                    {
                        gone.Delete();
                    }
                    DeviceKeyErrorCategory? whileStale = store.GetAsync(id).GetAwaiter().GetResult().Error?.Category;
                    DeviceKeyResult<DeviceKeyInfo> again = store.CreateAsync(new DeviceKeyCreateRequest { Scope = id.Scope, Alias = id.Alias }).GetAwaiter().GetResult();
                    DeviceKeyResult<DeviceKeyInfo> got = store.GetAsync(id).GetAwaiter().GetResult();
                    DeviceKeyResult<DeviceKeySignature> signed = store.SignAsync(id, new byte[] { 7 }).GetAwaiter().GetResult();
                    return new StaleOutcome(whileStale, again.Succeeded, again.Value?.Fingerprint != before.Fingerprint,
                        got.Succeeded && got.Value!.Fingerprint == again.Value?.Fingerprint,
                        signed.Succeeded && Verify(again.Value!.PublicKeySpki, new byte[] { 7 }, signed.Value!.Der),
                        store.ListAsync(id.Scope).GetAwaiter().GetResult().Value?.Count ?? -1);
                }
                finally
                {
                    store.DeleteAsync(id).GetAwaiter().GetResult();
                }
            })
        .TheTest
        .ShouldPass<StaleOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("while stale, the key is KeyNotFound", outcome.WhileStale == DeviceKeyErrorCategory.KeyNotFound);
            because.ItsTrue("creating the id again succeeds", outcome.Created);
            because.ItsTrue("it is a new key", outcome.NewKey);
            because.ItsTrue("GetAsync reports the new key", outcome.GotNewKey);
            because.ItsTrue("the new key signs", outcome.Signs);
            because.ItsTrue("only the new key is listed", outcome.Listed == 1);
        })
        .SoBeHappy()
        .UnlessItFailed();
        DeleteQuietly(records);
    }

    private static byte[] Nested(int length)
    {
        byte[] nested = new byte[length];
        for (int i = 0; i + 1 < length; i += 2)
        {
            nested[i] = 0x30;
            nested[i + 1] = 0x80;
        }
        return nested;
    }

    private static void DeleteQuietly(DirectoryInfo directory)
    {
        try
        {
            if (directory.Exists)
            {
                directory.Delete(true);
            }
        }
        catch (IOException)
        {
        }
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

    private sealed record NameOutcome(List<string> WronglyAccepted, List<string> WronglyRefused, bool SixtyFiveAccepted);

    private sealed record MangledOutcome(DeviceKeyErrorCategory? BadPrefix, int Thrown, int WrongFingerprint);

    private sealed record SurrogateOutcome(DeviceKeyErrorCategory? LoneHigh, DeviceKeyErrorCategory? LoneLow, bool PairAccepted, bool TagsAreArray);

    private sealed record DisposedOutcome(bool GotSameKey, DeviceKeyErrorCategory? Missing, DeviceKeyErrorCategory? UndefinedAccess, DeviceKeyErrorCategory? UndefinedProtection, DeviceKeyErrorCategory? BadListScope, DeviceKeyErrorCategory? CreateAfter, DeviceKeyErrorCategory? SignAfter, DeviceKeyErrorCategory? GetAfter, DeviceKeyErrorCategory? ListAfter, bool SupportedAfter);

    private sealed record BadRecordOutcome(DeviceKeyErrorCategory? Duplicate, List<DeviceKeyErrorCategory?> Categories, bool ListSucceeded, int Listed, bool GoneRecordKept, DeviceKeyErrorCategory? GoneCategory, bool GoneDeleted, int TemporaryFiles);

    private sealed record NestedOutcome(DeviceKeyErrorCategory? OverLimit, DeviceKeyErrorCategory? DeepNested, DeviceKeyErrorCategory? AtLimitNested, DeviceKeyErrorCategory? FingerprintNested);

    private sealed record RaceOutcome(int Thrown, int Unexpected);

    private sealed record BusyOutcome(int NotSupported, int Thrown, int Verified);

    private sealed record StaleOutcome(DeviceKeyErrorCategory? WhileStale, bool Created, bool NewKey, bool GotNewKey, bool Signs, int Listed);

    private sealed record BlockedOutcome(DeviceKeyErrorCategory? Blocked, bool KeyLeft, bool RetrySucceeded, int Listed);
}

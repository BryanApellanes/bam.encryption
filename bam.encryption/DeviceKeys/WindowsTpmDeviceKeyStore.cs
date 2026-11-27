using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Bam.Encryption.DeviceKeys;

/// <summary>
/// A device-key store that creates keys in the machine's TPM through the Microsoft Platform Crypto Provider. The
/// private key is created non-exportable inside the TPM and never leaves it; Windows can use it to sign but cannot
/// read it. Protection is <see cref="DeviceKeyProtection.Hardware"/>.
/// </summary>
/// <remarks>
/// <para>Off Windows, or on a machine with no usable TPM, every call fails with
/// <see cref="DeviceKeyErrorCategory.NotSupported"/>.</para>
/// <para>The only access policy for now is <see cref="DeviceKeyAccess.None"/>. Windows Hello prompts on TPM keys
/// (the provider's UI policy) are a later addition; until then the store refuses anything stronger rather than
/// creating a key that signs without the prompt the caller asked for.</para>
/// <para>No attestation yet: TPM key attestation through the provider is separate work, so
/// <see cref="DeviceKeyInfo.Attestation"/> is null even when a challenge is given.</para>
/// <para>CNG cannot list a provider's keys without native calls, and it keeps no creation time, so the store writes
/// one small public record per key beside the key: its creation time and access policy, nothing secret. Records are
/// written to a temporary file and moved into place, and a key whose record can't be written is deleted again, so a
/// failed create leaves nothing behind. Reads never delete: a key whose record is missing or unreadable is not listed
/// and <see cref="GetAsync"/> reports it as <see cref="DeviceKeyErrorCategory.PlatformFailure"/>; a record whose TPM
/// key is gone is not listed either, and <see cref="DeleteAsync"/> removes it.</para>
/// <para>File and TPM failures are reported as <see cref="DeviceKeyErrorCategory.PlatformFailure"/>, never thrown.
/// <see cref="DeviceKeyErrorCategory.NotSupported"/> means only that the provider has never worked in this process.</para>
/// <para>Creating takes a claim on the id (a named mutex on the key name), so two store instances or processes in
/// this logon session creating one id end with one key: one caller gets it, the others get
/// <see cref="DeviceKeyErrorCategory.AlreadyExists"/>. The claim is per logon session (<c>Local\</c>), so a service
/// and a desktop process of the same user don't share it. A record left behind by a key that is gone (a cleared
/// TPM, a crash) doesn't block creating that id again.</para>
/// <para>Calls into the TPM go through one gate, a named mutex every bam process of this logon session takes,
/// because the provider reports itself not ready under concurrent use. A provider failure is retried a few times;
/// a list either has every key or is a <see cref="DeviceKeyErrorCategory.PlatformFailure"/>, never a short success.
/// Calls run synchronously on the caller's thread; a UI app should call from a background thread.</para>
/// </remarks>
public sealed class WindowsTpmDeviceKeyStore : IDeviceKeyStore
{
    /// <summary>The CNG provider that keeps keys in the TPM.</summary>
    public const string ProviderName = "Microsoft Platform Crypto Provider";

    private const string KeyNamePrefix = "bam.devicekey.";

    private static readonly IReadOnlyList<DeviceKeyAccess> Supported = Array.AsReadOnly(new[] { DeviceKeyAccess.None });

    private readonly DirectoryInfo _records;

    private readonly TimeProvider _clock;

    private const string GateName = @"Local\bam.devicekey.tpm-gate";

    private const int ProbeAttempts = 10;

    private const int TpmAttempts = 3;

    private static readonly TimeSpan ProbeDelay = TimeSpan.FromMilliseconds(200);

    private static readonly TimeSpan RetryDelay = TimeSpan.FromMilliseconds(100);

    private static readonly TimeSpan GateTimeout = TimeSpan.FromSeconds(10);

    private static readonly TimeSpan ClaimTimeout = TimeSpan.FromSeconds(5);

    private static volatile bool _providerWorked;

    /// <summary>
    /// Creates a store that keeps its key records under <c>~/.bam/devicekeys/tpm</c>.
    /// </summary>
    public WindowsTpmDeviceKeyStore() : this(new DirectoryInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".bam", "devicekeys", "tpm")), TimeProvider.System)
    {
    }

    /// <summary>
    /// Creates a store.
    /// </summary>
    /// <param name="records">Where the public key records go.</param>
    /// <param name="clock">The clock that stamps <see cref="DeviceKeyInfo.CreatedUtc"/>.</param>
    public WindowsTpmDeviceKeyStore(DirectoryInfo records, TimeProvider clock)
    {
        _records = records ?? throw new ArgumentNullException(nameof(records));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    /// <inheritdoc />
    /// <remarks><see cref="DeviceKeyCapabilities.Protection"/> is the protection the store gives when it is supported;
    /// check <see cref="DeviceKeyCapabilities.IsSupported"/> first.</remarks>
    public Task<DeviceKeyCapabilities> GetCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        string? reason = UnsupportedReason();
        return Task.FromResult(new DeviceKeyCapabilities
        {
            IsSupported = reason == null,
            Protection = DeviceKeyProtection.Hardware,
            SupportedAccess = reason == null ? Supported : Array.Empty<DeviceKeyAccess>(),
            SupportsAttestation = false,
            Reason = reason,
        });
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<DeviceKeyInfo>> CreateAsync(DeviceKeyCreateRequest request, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<DeviceKeyInfo>? refused = DeviceKeyRequests.CheckCreate<DeviceKeyInfo>(request, Supported, DeviceKeyProtection.Hardware, cancellationToken, false) ?? Unsupported<DeviceKeyInfo>();
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        DeviceKeyId id = new DeviceKeyId(request.Scope, request.Alias ?? DeviceKeyId.NewAlias());
        return Task.FromResult(OperatingSystem.IsWindows()
            ? Create(id, request.Access)
            : DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.NotSupported, "The TPM store needs Windows."));
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<DeviceKeySignature>> SignAsync(DeviceKeyId id, byte[] data, string? promptReason = null, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<DeviceKeySignature>? refused = DeviceKeyRequests.CheckSign<DeviceKeySignature>(id, data, cancellationToken, false) ?? Unsupported<DeviceKeySignature>();
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        return Task.FromResult(OperatingSystem.IsWindows()
            ? Sign(id, data)
            : DeviceKeyResult<DeviceKeySignature>.Failure(DeviceKeyErrorCategory.NotSupported, "The TPM store needs Windows."));
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<DeviceKeyInfo>> GetAsync(DeviceKeyId id, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<DeviceKeyInfo>? refused = DeviceKeyRequests.CheckId<DeviceKeyInfo>(id, cancellationToken, false) ?? Unsupported<DeviceKeyInfo>();
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        return Task.FromResult(OperatingSystem.IsWindows()
            ? Describe(id).Result
            : DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.NotSupported, "The TPM store needs Windows."));
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>> ListAsync(string scope, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>? refused = DeviceKeyRequests.CheckScope<IReadOnlyList<DeviceKeyInfo>>(scope, cancellationToken, false) ?? Unsupported<IReadOnlyList<DeviceKeyInfo>>();
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult(DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>.Failure(DeviceKeyErrorCategory.NotSupported, "The TPM store needs Windows."));
        }
        DirectoryInfo scopeDirectory = new DirectoryInfo(Path.Combine(_records.FullName, scope));
        List<DeviceKeyInfo> keys = new List<DeviceKeyInfo>();
        FileInfo[] records;
        try
        {
            records = scopeDirectory.Exists ? scopeDirectory.GetFiles("*.json") : Array.Empty<FileInfo>();
        }
        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
        {
            return Task.FromResult(DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The key records for scope '{scope}' could not be read: {ex.Message}"));
        }
        foreach (FileInfo record in records)
        {
            string alias = Path.GetFileNameWithoutExtension(record.Name);
            if (!DeviceKeyId.IsValidName(alias))
            {
                continue;
            }
            TpmAttempt<DeviceKeyInfo> described = Describe(new DeviceKeyId(scope, alias));
            if (described.Transient)
            {
                // The provider failed, not the key: a list without this key would be a wrong answer.
                return Task.FromResult(DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM was busy while listing scope '{scope}': {described.Result.Error?.Message}"));
            }
            if (described.Result.Succeeded && described.Result.Value != null)
            {
                keys.Add(described.Result.Value);
            }
        }
        List<DeviceKeyInfo> ordered = keys.OrderBy(info => info.CreatedUtc).ThenBy(info => info.Id.Alias, StringComparer.Ordinal).ToList();
        return Task.FromResult(DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>.Success(ordered));
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<bool>> DeleteAsync(DeviceKeyId id, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<bool>? refused = DeviceKeyRequests.CheckId<bool>(id, cancellationToken, false) ?? Unsupported<bool>();
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        return Task.FromResult(OperatingSystem.IsWindows()
            ? Delete(id)
            : DeviceKeyResult<bool>.Failure(DeviceKeyErrorCategory.NotSupported, "The TPM store needs Windows."));
    }

    /// <summary>
    /// The CNG key name for a device key. Scope and alias use only <c>a-z 0-9 . _ -</c>, and <c>+</c> separates them, so the name is unambiguous.
    /// </summary>
    /// <param name="id">The key.</param>
    /// <returns>The key name.</returns>
    internal static string KeyNameOf(DeviceKeyId id)
    {
        return $"{KeyNamePrefix}{id.Scope}+{id.Alias}";
    }

    private DeviceKeyResult<T>? Unsupported<T>()
    {
        string? reason = UnsupportedReason();
        return reason == null ? null : DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.NotSupported, reason);
    }

    private static string? UnsupportedReason()
    {
        if (!OperatingSystem.IsWindows())
        {
            return "The TPM store needs Windows.";
        }
        return ProbeProvider();
    }

    /// <summary>
    /// Whether the provider is there. A success is remembered for the life of the process: after that a provider
    /// failure means the TPM is busy or broken, which is <see cref="DeviceKeyErrorCategory.PlatformFailure"/>, not
    /// <see cref="DeviceKeyErrorCategory.NotSupported"/>. Before the first success the probe tries for about two
    /// seconds, under the gate, so a TPM that another program is using isn't reported as missing.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static string? ProbeProvider()
    {
        if (_providerWorked)
        {
            return null;
        }
        string reason = string.Empty;
        for (int attempt = 0; attempt < ProbeAttempts; attempt++)
        {
            TpmAttempt<bool> probed = UnderGate(() =>
            {
                try
                {
                    CngKey.Exists(KeyNamePrefix + "probe", new CngProvider(ProviderName));
                    return new TpmAttempt<bool>(DeviceKeyResult<bool>.Success(true), false);
                }
                catch (CryptographicException ex)
                {
                    return new TpmAttempt<bool>(DeviceKeyResult<bool>.Failure(DeviceKeyErrorCategory.PlatformFailure, ex.Message), true);
                }
            });
            if (probed.Result.Succeeded)
            {
                _providerWorked = true;
                return null;
            }
            reason = probed.Result.Error?.Message ?? string.Empty;
            if (!probed.Transient)
            {
                break;
            }
            if (attempt + 1 < ProbeAttempts)
            {
                Thread.Sleep(ProbeDelay);
            }
        }
        return $"No usable TPM: {reason}";
    }

    [SupportedOSPlatform("windows")]
    private DeviceKeyResult<DeviceKeyInfo> Create(DeviceKeyId id, DeviceKeyAccess access)
    {
        // The claim is a named mutex on the key name, so it holds across store instances, record directories and the
        // processes of this logon session. Whoever holds it is the only caller that may create, or roll back, this
        // key. A caller that finds it taken waits briefly and then answers from the TPM.
        Mutex claim;
        try
        {
            claim = new Mutex(false, ClaimNameOf(id));
        }
        catch (Exception ex) when (ex is WaitHandleCannotBeOpenedException || ex is UnauthorizedAccessException || ex is IOException)
        {
            return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The claim on key '{id.Alias}' in scope '{id.Scope}' could not be opened: {ex.Message}");
        }
        using (claim)
        {
            bool claimed;
            try
            {
                claimed = claim.WaitOne(ClaimTimeout);
            }
            catch (AbandonedMutexException)
            {
                claimed = true;
            }
            if (!claimed)
            {
                return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"Another caller has been creating key '{id.Alias}' in scope '{id.Scope}' for {ClaimTimeout.TotalSeconds:0} seconds; try again.");
            }
            try
            {
                return UnderGate(() => new TpmAttempt<DeviceKeyInfo>(CreateClaimed(id, access), false)).Result;
            }
            finally
            {
                claim.ReleaseMutex();
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private DeviceKeyResult<DeviceKeyInfo> CreateClaimed(DeviceKeyId id, DeviceKeyAccess access)
    {
        CngProvider provider = new CngProvider(ProviderName);
        FileInfo file = RecordFileOf(id);
        try
        {
            if (CngKey.Exists(KeyNameOf(id), provider))
            {
                return AlreadyExists(id);
            }
        }
        catch (CryptographicException ex)
        {
            return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM could not be asked about the key: {ex.Message}");
        }
        // No TPM key under this name, so any record here is a leftover (a cleared TPM, a crash): the new record
        // replaces it.
        CngKeyCreationParameters parameters = new CngKeyCreationParameters
        {
            Provider = provider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing,
            KeyCreationOptions = CngKeyCreationOptions.None,
        };
        CngKey key;
        try
        {
            key = CngKey.Create(CngAlgorithm.ECDsaP256, KeyNameOf(id), parameters);
        }
        catch (CryptographicException ex)
        {
            // This call created nothing, so nothing is rolled back.
            return ExistsQuietly(id, provider)
                ? AlreadyExists(id)
                : DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM did not create the key: {ex.Message}");
        }
        using (key)
        {
            try
            {
                byte[] spki;
                using (ECDsaCng ecdsa = new ECDsaCng(key))
                {
                    spki = ecdsa.ExportSubjectPublicKeyInfo();
                }
                DeviceKeyRecord record = new DeviceKeyRecord { CreatedUtc = _clock.GetUtcNow(), Access = access };
                WriteRecord(file, record);
                return DeviceKeyResult<DeviceKeyInfo>.Success(CanonicalSpki.Describe(id, spki, record.CreatedUtc, DeviceKeyProtection.Hardware, access));
            }
            catch (Exception ex)
            {
                // This call created the key and holds the claim, so removing it removes nobody else's key.
                string rollback = DeleteQuietly(key);
                return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The key's record could not be written, so the key was not kept: {ex.Message}{rollback}");
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static DeviceKeyResult<DeviceKeySignature> Sign(DeviceKeyId id, byte[] data)
    {
        return WithTpm(() =>
        {
            CngProvider provider = new CngProvider(ProviderName);
            try
            {
                if (!CngKey.Exists(KeyNameOf(id), provider))
                {
                    return new TpmAttempt<DeviceKeySignature>(DeviceKeyRequests.NotFound<DeviceKeySignature>(id), false);
                }
                using CngKey key = CngKey.Open(KeyNameOf(id), provider);
                using ECDsaCng ecdsa = new ECDsaCng(key);
                byte[] der = ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
                return new TpmAttempt<DeviceKeySignature>(DeviceKeyResult<DeviceKeySignature>.Success(new DeviceKeySignature { Id = id, Der = der }), false);
            }
            catch (ArgumentException ex)
            {
                // A key under this name that is not an ECDSA key: retrying won't help.
                return new TpmAttempt<DeviceKeySignature>(DeviceKeyResult<DeviceKeySignature>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM did not sign: {ex.Message}"), false);
            }
            catch (CryptographicException ex)
            {
                // Usually a TPM busy with another program; try again shortly.
                return new TpmAttempt<DeviceKeySignature>(DeviceKeyResult<DeviceKeySignature>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM did not sign: {ex.Message}"), true);
            }
        }).Result;
    }

    /// <summary>
    /// Describes one key. <see cref="TpmAttempt{T}.Transient"/> is true when the provider itself failed after the
    /// retries, as opposed to the key being gone or its record being bad.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private TpmAttempt<DeviceKeyInfo> Describe(DeviceKeyId id)
    {
        FileInfo file = RecordFileOf(id);
        return WithTpm(() =>
        {
            CngProvider provider = new CngProvider(ProviderName);
            try
            {
                if (!CngKey.Exists(KeyNameOf(id), provider))
                {
                    // A read never deletes: a stale record stays until DeleteAsync removes it or CreateAsync replaces it.
                    return new TpmAttempt<DeviceKeyInfo>(DeviceKeyRequests.NotFound<DeviceKeyInfo>(id), false);
                }
                DeviceKeyRecord? record = ReadRecord(file);
                if (record == null)
                {
                    return new TpmAttempt<DeviceKeyInfo>(DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The record for key '{id.Alias}' in scope '{id.Scope}' is missing or unreadable."), false);
                }
                if (!Enum.IsDefined(record.Access) || !Supported.Contains(record.Access))
                {
                    return new TpmAttempt<DeviceKeyInfo>(DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The record for key '{id.Alias}' in scope '{id.Scope}' names access '{record.Access}', which this store does not create."), false);
                }
                using CngKey key = CngKey.Open(KeyNameOf(id), provider);
                using ECDsaCng ecdsa = new ECDsaCng(key);
                return new TpmAttempt<DeviceKeyInfo>(DeviceKeyResult<DeviceKeyInfo>.Success(CanonicalSpki.Describe(id, ecdsa.ExportSubjectPublicKeyInfo(), record.CreatedUtc, DeviceKeyProtection.Hardware, record.Access)), false);
            }
            catch (CryptographicException ex)
            {
                return new TpmAttempt<DeviceKeyInfo>(DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM did not open the key: {ex.Message}"), true);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException)
            {
                return new TpmAttempt<DeviceKeyInfo>(DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The key could not be read: {ex.Message}"), false);
            }
        });
    }

    [SupportedOSPlatform("windows")]
    private DeviceKeyResult<bool> Delete(DeviceKeyId id)
    {
        FileInfo file = RecordFileOf(id);
        return WithTpm(() =>
        {
            // The record goes first: if it can't be removed, nothing has changed and the caller can simply retry.
            try
            {
                if (file.Exists)
                {
                    file.Delete();
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return new TpmAttempt<bool>(DeviceKeyResult<bool>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The key's record could not be removed, so nothing was deleted: {ex.Message}"), false);
            }
            CngProvider provider = new CngProvider(ProviderName);
            try
            {
                if (!CngKey.Exists(KeyNameOf(id), provider))
                {
                    return new TpmAttempt<bool>(DeviceKeyResult<bool>.Success(false), false);
                }
                using CngKey key = CngKey.Open(KeyNameOf(id), provider);
                key.Delete();
                return new TpmAttempt<bool>(DeviceKeyResult<bool>.Success(true), false);
            }
            catch (CryptographicException ex)
            {
                return new TpmAttempt<bool>(DeviceKeyResult<bool>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM did not delete the key: {ex.Message}"), true);
            }
        }).Result;
    }

    /// <summary>
    /// Runs one TPM operation under the gate, retrying a transient provider failure a few times.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static TpmAttempt<T> WithTpm<T>(Func<TpmAttempt<T>> operation)
    {
        TpmAttempt<T> last = UnderGate(operation);
        for (int attempt = 1; attempt < TpmAttempts && last.Transient; attempt++)
        {
            Thread.Sleep(RetryDelay);
            last = UnderGate(operation);
        }
        return last;
    }

    /// <summary>
    /// Runs one TPM operation while holding the gate: a named mutex every bam process of this logon session takes
    /// before calling the provider, because the provider reports itself not ready under concurrent use. A gate that
    /// stays taken past <see cref="GateTimeout"/> is a transient failure.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static TpmAttempt<T> UnderGate<T>(Func<TpmAttempt<T>> operation)
    {
        Mutex gate;
        try
        {
            gate = new Mutex(false, GateName);
        }
        catch (Exception ex) when (ex is WaitHandleCannotBeOpenedException || ex is UnauthorizedAccessException || ex is IOException)
        {
            return new TpmAttempt<T>(DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM gate could not be opened: {ex.Message}"), false);
        }
        using (gate)
        {
            bool held;
            try
            {
                held = gate.WaitOne(GateTimeout);
            }
            catch (AbandonedMutexException)
            {
                held = true;
            }
            if (!held)
            {
                return new TpmAttempt<T>(DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM stayed busy for {GateTimeout.TotalSeconds:0} seconds."), true);
            }
            try
            {
                return operation();
            }
            finally
            {
                gate.ReleaseMutex();
            }
        }
    }

    private FileInfo RecordFileOf(DeviceKeyId id)
    {
        return new FileInfo(Path.Combine(_records.FullName, id.Scope, id.Alias + ".json"));
    }

    private static string ClaimNameOf(DeviceKeyId id)
    {
        return $@"Local\{KeyNameOf(id)}";
    }

    private static DeviceKeyResult<DeviceKeyInfo> AlreadyExists(DeviceKeyId id)
    {
        return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.AlreadyExists, $"A key '{id.Alias}' already exists in scope '{id.Scope}'.");
    }

    [SupportedOSPlatform("windows")]
    private static bool ExistsQuietly(DeviceKeyId id, CngProvider provider)
    {
        try
        {
            return CngKey.Exists(KeyNameOf(id), provider);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private static string DeleteQuietly(CngKey key)
    {
        try
        {
            key.Delete();
            return string.Empty;
        }
        catch (CryptographicException ex)
        {
            return $" Removing the key also failed: {ex.Message}";
        }
    }

    /// <summary>
    /// Writes a record to a temporary file beside it and moves it into place, replacing any leftover record, so a
    /// crash never leaves a partial record. Callers hold the id's claim, so the temporary name is fixed per id and a
    /// temporary file left by a crash is overwritten by the next create.
    /// </summary>
    private static void WriteRecord(FileInfo file, DeviceKeyRecord record)
    {
        DirectoryInfo directory = file.Directory ?? throw new IOException($"'{file.FullName}' has no directory.");
        directory.Create();
        string temporary = Path.Combine(directory.FullName, $".{Path.GetFileNameWithoutExtension(file.Name)}.tmp");
        try
        {
            File.WriteAllText(temporary, record.ToJson());
            File.Move(temporary, file.FullName, true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    /// <summary>
    /// Reads a record, or null when it is missing, empty, not a record, or has no creation time.
    /// </summary>
    private static DeviceKeyRecord? ReadRecord(FileInfo file)
    {
        if (!file.Exists)
        {
            return null;
        }
        string json = File.ReadAllText(file.FullName);
        if (string.IsNullOrWhiteSpace(json) || !json.TryFromJson<DeviceKeyRecord>(out DeviceKeyRecord record) || record == null || record.CreatedUtc == default)
        {
            return null;
        }
        return record;
    }

    /// <summary>
    /// One TPM operation's result, and whether it failed in a way a retry may fix (the provider was busy).
    /// </summary>
    private sealed record TpmAttempt<T>(DeviceKeyResult<T> Result, bool Transient);

    /// <summary>
    /// The public record kept beside each TPM key.
    /// </summary>
    internal sealed class DeviceKeyRecord
    {
        /// <summary>When the key was created.</summary>
        public DateTimeOffset CreatedUtc { get; set; }

        /// <summary>The key's access policy.</summary>
        public DeviceKeyAccess Access { get; set; }
    }
}

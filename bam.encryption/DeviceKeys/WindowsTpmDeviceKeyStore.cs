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
/// <see cref="DeviceKeyErrorCategory.NotSupported"/> means only that the provider itself has not worked in this
/// process; a gate that can't be taken says nothing about the TPM and is never reported as
/// <see cref="DeviceKeyErrorCategory.NotSupported"/>.</para>
/// <para>Creating takes a claim on the id (a named mutex on the key name), so two store instances or processes in
/// this logon session creating one id end with one key: one caller gets it, the others get
/// <see cref="DeviceKeyErrorCategory.AlreadyExists"/>. The claim is per logon session (<c>Local\</c>), so a service
/// and a desktop process of the same user don't share it. A record left behind by a key that is gone (a cleared
/// TPM, a crash) doesn't block creating that id again.</para>
/// <para>Calls into the TPM go through one gate, a named mutex every bam process of this logon session takes,
/// because the provider reports itself not ready under concurrent use. Every TPM call, create included, retries a
/// provider failure a few times; a gate that can't be opened or taken is not retried. A list either has every key
/// or is a <see cref="DeviceKeyErrorCategory.PlatformFailure"/>, never a short success. Waits for the gate and the
/// claim end when the caller's token is cancelled. Calls run synchronously on the caller's thread; a UI app should
/// call from a background thread.</para>
/// </remarks>
public sealed class WindowsTpmDeviceKeyStore : IDeviceKeyStore
{
    /// <summary>The CNG provider that keeps keys in the TPM.</summary>
    public const string ProviderName = "Microsoft Platform Crypto Provider";

    private const string KeyNamePrefix = "bam.devicekey.";

    private const int ProbeAttempts = 10;

    private const int TpmAttempts = 3;

    private static readonly IReadOnlyList<DeviceKeyAccess> Supported = Array.AsReadOnly(new[] { DeviceKeyAccess.None });

    private static readonly TimeSpan ProbeDelay = TimeSpan.FromMilliseconds(200);

    private static readonly TimeSpan RetryDelay = TimeSpan.FromMilliseconds(100);

    private static volatile bool _providerWorked;

    private readonly DirectoryInfo _records;

    private readonly TimeProvider _clock;

    private readonly TpmGateSettings _settings;

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
    public WindowsTpmDeviceKeyStore(DirectoryInfo records, TimeProvider clock) : this(records, clock, TpmGateSettings.Default)
    {
    }

    /// <summary>
    /// Creates a store with its own gate name and timeouts, so tests can hold or squat the gate without touching
    /// other processes' TPM calls.
    /// </summary>
    internal WindowsTpmDeviceKeyStore(DirectoryInfo records, TimeProvider clock, TpmGateSettings settings)
    {
        _records = records ?? throw new ArgumentNullException(nameof(records));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
    }

    /// <inheritdoc />
    /// <remarks><see cref="DeviceKeyCapabilities.Protection"/> is the protection the store gives when it is supported;
    /// check <see cref="DeviceKeyCapabilities.IsSupported"/> first.</remarks>
    public Task<DeviceKeyCapabilities> GetCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        string? reason = UnsupportedReason(cancellationToken);
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
        DeviceKeyResult<DeviceKeyInfo>? refused = DeviceKeyRequests.CheckCreate<DeviceKeyInfo>(request, Supported, DeviceKeyProtection.Hardware, cancellationToken, false) ?? Unsupported<DeviceKeyInfo>(cancellationToken);
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        DeviceKeyId id = new DeviceKeyId(request.Scope, request.Alias ?? DeviceKeyId.NewAlias());
        return Task.FromResult(OperatingSystem.IsWindows()
            ? Create(id, request.Access, cancellationToken)
            : DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.NotSupported, "The TPM store needs Windows."));
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<DeviceKeySignature>> SignAsync(DeviceKeyId id, byte[] data, string? promptReason = null, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<DeviceKeySignature>? refused = DeviceKeyRequests.CheckSign<DeviceKeySignature>(id, data, cancellationToken, false) ?? Unsupported<DeviceKeySignature>(cancellationToken);
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        return Task.FromResult(OperatingSystem.IsWindows()
            ? Sign(id, data, cancellationToken)
            : DeviceKeyResult<DeviceKeySignature>.Failure(DeviceKeyErrorCategory.NotSupported, "The TPM store needs Windows."));
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<DeviceKeyInfo>> GetAsync(DeviceKeyId id, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<DeviceKeyInfo>? refused = DeviceKeyRequests.CheckId<DeviceKeyInfo>(id, cancellationToken, false) ?? Unsupported<DeviceKeyInfo>(cancellationToken);
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        return Task.FromResult(OperatingSystem.IsWindows()
            ? Describe(id, cancellationToken).Result
            : DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.NotSupported, "The TPM store needs Windows."));
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>> ListAsync(string scope, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>? refused = DeviceKeyRequests.CheckScope<IReadOnlyList<DeviceKeyInfo>>(scope, cancellationToken, false) ?? Unsupported<IReadOnlyList<DeviceKeyInfo>>(cancellationToken);
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
            TpmAttempt<DeviceKeyInfo> described = Describe(new DeviceKeyId(scope, alias), cancellationToken);
            if (described.Result.Succeeded && described.Result.Value != null)
            {
                keys.Add(described.Result.Value);
                continue;
            }
            if (described.Skippable || described.Result.Error?.Category == DeviceKeyErrorCategory.KeyNotFound)
            {
                // The key is gone or its record is bad: it isn't one of this scope's keys.
                continue;
            }
            // Anything else (a busy TPM, a gate that can't be taken, a record that can't be read, a cancelled wait)
            // says nothing about whether the key exists, so a list without it would be a wrong answer.
            DeviceKeyErrorCategory category = described.Result.Error?.Category == DeviceKeyErrorCategory.Cancelled ? DeviceKeyErrorCategory.Cancelled : DeviceKeyErrorCategory.PlatformFailure;
            return Task.FromResult(DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>.Failure(category, $"Scope '{scope}' could not be listed completely: {described.Result.Error?.Message}"));
        }
        List<DeviceKeyInfo> ordered = keys.OrderBy(info => info.CreatedUtc).ThenBy(info => info.Id.Alias, StringComparer.Ordinal).ToList();
        return Task.FromResult(DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>.Success(ordered));
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<bool>> DeleteAsync(DeviceKeyId id, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<bool>? refused = DeviceKeyRequests.CheckId<bool>(id, cancellationToken, false) ?? Unsupported<bool>(cancellationToken);
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        return Task.FromResult(OperatingSystem.IsWindows()
            ? Delete(id, cancellationToken)
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

    /// <summary>
    /// The name of the claim a create takes on a key id.
    /// </summary>
    /// <param name="id">The key.</param>
    /// <returns>The mutex name.</returns>
    internal static string ClaimNameOf(DeviceKeyId id)
    {
        return $@"Local\{KeyNameOf(id)}";
    }

    private DeviceKeyResult<T>? Unsupported<T>(CancellationToken cancellationToken)
    {
        string? reason = UnsupportedReason(cancellationToken);
        return reason == null ? null : DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.NotSupported, reason);
    }

    private string? UnsupportedReason(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return "The TPM store needs Windows.";
        }
        return ProbeProvider(cancellationToken);
    }

    /// <summary>
    /// Whether the provider is there. A success is remembered for the life of the process: after that a provider
    /// failure means the TPM is busy or broken, which is <see cref="DeviceKeyErrorCategory.PlatformFailure"/>, not
    /// <see cref="DeviceKeyErrorCategory.NotSupported"/>. Before the first success the probe tries for about two
    /// seconds, under the gate, so a TPM that other bam processes are using isn't reported as missing; heavy load
    /// from programs outside the gate can still exhaust it (bam.encryption#26). A gate that can't be opened or taken,
    /// or a cancelled wait, says nothing about the TPM: the probe stops and answers "supported" without remembering
    /// it, and the call itself then reports the failure.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private string? ProbeProvider(CancellationToken cancellationToken)
    {
        if (_settings.RememberProbe && _providerWorked)
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
            }, cancellationToken);
            if (probed.GateFailed)
            {
                return null;
            }
            if (probed.Result.Succeeded)
            {
                if (_settings.RememberProbe)
                {
                    _providerWorked = true;
                }
                return null;
            }
            reason = probed.Result.Error?.Message ?? string.Empty;
            if (!probed.Transient)
            {
                break;
            }
            if (attempt + 1 < ProbeAttempts && cancellationToken.WaitHandle.WaitOne(ProbeDelay))
            {
                return null;
            }
        }
        return $"No usable TPM: {reason}";
    }

    [SupportedOSPlatform("windows")]
    private DeviceKeyResult<DeviceKeyInfo> Create(DeviceKeyId id, DeviceKeyAccess access, CancellationToken cancellationToken)
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
            Taken taken = Take(claim, _settings.ClaimTimeout, cancellationToken);
            if (taken == Taken.Cancelled)
            {
                return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.Cancelled, "The operation was cancelled.");
            }
            if (taken == Taken.TimedOut)
            {
                return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"Another caller has been creating key '{id.Alias}' in scope '{id.Scope}' for {_settings.ClaimTimeout.TotalSeconds:0.#} seconds; try again.");
            }
            try
            {
                // The claim is held for every try, so a retry can't race another creator.
                return WithTpm(() => CreateClaimed(id, access), cancellationToken).Result;
            }
            finally
            {
                claim.ReleaseMutex();
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private TpmAttempt<DeviceKeyInfo> CreateClaimed(DeviceKeyId id, DeviceKeyAccess access)
    {
        CngProvider provider = new CngProvider(ProviderName);
        FileInfo file = RecordFileOf(id);
        try
        {
            if (CngKey.Exists(KeyNameOf(id), provider))
            {
                return new TpmAttempt<DeviceKeyInfo>(AlreadyExists(id), false);
            }
        }
        catch (CryptographicException ex)
        {
            return new TpmAttempt<DeviceKeyInfo>(DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM could not be asked about the key: {ex.Message}"), true);
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
            // This call created nothing, so nothing is rolled back. With no key under the name, the TPM was most
            // likely busy and the next try may work.
            return ExistsQuietly(id, provider)
                ? new TpmAttempt<DeviceKeyInfo>(AlreadyExists(id), false)
                : new TpmAttempt<DeviceKeyInfo>(DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM did not create the key: {ex.Message}"), true);
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
                return new TpmAttempt<DeviceKeyInfo>(DeviceKeyResult<DeviceKeyInfo>.Success(CanonicalSpki.Describe(id, spki, record.CreatedUtc, DeviceKeyProtection.Hardware, access)), false);
            }
            catch (Exception ex)
            {
                // This call created the key and holds the claim, so removing it removes nobody else's key.
                string rollback = DeleteQuietly(key);
                return new TpmAttempt<DeviceKeyInfo>(DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The key's record could not be written, so the key was not kept: {ex.Message}{rollback}"), false);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private DeviceKeyResult<DeviceKeySignature> Sign(DeviceKeyId id, byte[] data, CancellationToken cancellationToken)
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
        }, cancellationToken).Result;
    }

    /// <summary>
    /// Describes one key. <see cref="TpmAttempt{T}.Skippable"/> is true only when the key is gone or its record is
    /// missing or bad, the cases a list leaves out.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private TpmAttempt<DeviceKeyInfo> Describe(DeviceKeyId id, CancellationToken cancellationToken)
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
                    return new TpmAttempt<DeviceKeyInfo>(DeviceKeyRequests.NotFound<DeviceKeyInfo>(id), false, Skippable: true);
                }
                DeviceKeyRecord? record = ReadRecord(file);
                if (record == null)
                {
                    return new TpmAttempt<DeviceKeyInfo>(DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The record for key '{id.Alias}' in scope '{id.Scope}' is missing or unreadable."), false, Skippable: true);
                }
                if (!Enum.IsDefined(record.Access) || !Supported.Contains(record.Access))
                {
                    return new TpmAttempt<DeviceKeyInfo>(DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The record for key '{id.Alias}' in scope '{id.Scope}' names access '{record.Access}', which this store does not create."), false, Skippable: true);
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
        }, cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    private DeviceKeyResult<bool> Delete(DeviceKeyId id, CancellationToken cancellationToken)
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
        }, cancellationToken).Result;
    }

    /// <summary>
    /// Runs one TPM operation under the gate, retrying a provider failure a few times. A gate that can't be opened
    /// or taken, or a cancelled wait, is not retried: it has already waited, and a retry won't change it.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private TpmAttempt<T> WithTpm<T>(Func<TpmAttempt<T>> operation, CancellationToken cancellationToken)
    {
        TpmAttempt<T> last = UnderGate(operation, cancellationToken);
        for (int attempt = 1; attempt < TpmAttempts && last.Transient && !last.GateFailed; attempt++)
        {
            if (cancellationToken.WaitHandle.WaitOne(RetryDelay))
            {
                return new TpmAttempt<T>(DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.Cancelled, "The operation was cancelled."), false, GateFailed: true);
            }
            last = UnderGate(operation, cancellationToken);
        }
        return last;
    }

    /// <summary>
    /// Runs one TPM operation while holding the gate: a named mutex every bam process of this logon session takes
    /// before calling the provider, because the provider reports itself not ready under concurrent use. A gate that
    /// can't be opened, stays taken past the gate timeout, or whose wait is cancelled comes back with
    /// <see cref="TpmAttempt{T}.GateFailed"/> set and the operation not run.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private TpmAttempt<T> UnderGate<T>(Func<TpmAttempt<T>> operation, CancellationToken cancellationToken)
    {
        Mutex gate;
        try
        {
            gate = new Mutex(false, _settings.GateName);
        }
        catch (Exception ex) when (ex is WaitHandleCannotBeOpenedException || ex is UnauthorizedAccessException || ex is IOException)
        {
            return new TpmAttempt<T>(DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM gate could not be opened: {ex.Message}"), true, GateFailed: true);
        }
        using (gate)
        {
            Taken taken = Take(gate, _settings.GateTimeout, cancellationToken);
            if (taken == Taken.Cancelled)
            {
                return new TpmAttempt<T>(DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.Cancelled, "The operation was cancelled."), false, GateFailed: true);
            }
            if (taken == Taken.TimedOut)
            {
                return new TpmAttempt<T>(DeviceKeyResult<T>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM gate stayed taken for {_settings.GateTimeout.TotalSeconds:0.#} seconds."), true, GateFailed: true);
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

    /// <summary>
    /// Waits for a mutex, the timeout, or the token. An abandoned mutex counts as taken: its holder ended without
    /// releasing it, and what it guarded is checked again by the caller.
    /// </summary>
    private static Taken Take(Mutex mutex, TimeSpan timeout, CancellationToken cancellationToken)
    {
        int index;
        try
        {
            index = cancellationToken.CanBeCanceled
                ? WaitHandle.WaitAny(new WaitHandle[] { mutex, cancellationToken.WaitHandle }, timeout)
                : (mutex.WaitOne(timeout) ? 0 : WaitHandle.WaitTimeout);
        }
        catch (AbandonedMutexException)
        {
            return Taken.Held;
        }
        if (index == 0)
        {
            return Taken.Held;
        }
        return index == WaitHandle.WaitTimeout ? Taken.TimedOut : Taken.Cancelled;
    }

    private FileInfo RecordFileOf(DeviceKeyId id)
    {
        return new FileInfo(Path.Combine(_records.FullName, id.Scope, id.Alias + ".json"));
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

    private enum Taken
    {
        Held,
        TimedOut,
        Cancelled,
    }

    /// <summary>
    /// One TPM operation's result. <c>Transient</c>: a retry may fix it (the provider was busy). <c>Skippable</c>:
    /// the key is gone or its record is bad, so a list leaves it out. <c>GateFailed</c>: the gate couldn't be taken
    /// or the wait was cancelled, so the operation didn't run and nothing is known about the TPM.
    /// </summary>
    private sealed record TpmAttempt<T>(DeviceKeyResult<T> Result, bool Transient, bool Skippable = false, bool GateFailed = false);

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

/// <summary>
/// The gate and claim settings of a <see cref="WindowsTpmDeviceKeyStore"/>. Only tests change them.
/// </summary>
/// <param name="GateName">The named mutex every TPM call takes.</param>
/// <param name="GateTimeout">How long a call waits for the gate.</param>
/// <param name="ClaimTimeout">How long a create waits for another creator of the same id.</param>
/// <param name="RememberProbe">Whether a working provider is remembered for the process; false makes every call probe.</param>
internal sealed record TpmGateSettings(string GateName, TimeSpan GateTimeout, TimeSpan ClaimTimeout, bool RememberProbe)
{
    /// <summary>The settings every real store uses.</summary>
    public static TpmGateSettings Default { get; } = new TpmGateSettings(@"Local\bam.devicekey.tpm-gate", TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5), true);
}

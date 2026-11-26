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
/// <para>File and TPM failures are reported as <see cref="DeviceKeyErrorCategory.PlatformFailure"/>, never thrown.</para>
/// </remarks>
public sealed class WindowsTpmDeviceKeyStore : IDeviceKeyStore
{
    /// <summary>The CNG provider that keeps keys in the TPM.</summary>
    public const string ProviderName = "Microsoft Platform Crypto Provider";

    private const string KeyNamePrefix = "bam.devicekey.";

    private static readonly IReadOnlyList<DeviceKeyAccess> Supported = Array.AsReadOnly(new[] { DeviceKeyAccess.None });

    private readonly DirectoryInfo _records;

    private readonly TimeProvider _clock;

    private readonly object _sync = new object();

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
            ? Describe(id)
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
            DeviceKeyResult<DeviceKeyInfo> described = Describe(new DeviceKeyId(scope, alias));
            if (described.Succeeded && described.Value != null)
            {
                keys.Add(described.Value);
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

    [SupportedOSPlatform("windows")]
    private static string? ProbeProvider()
    {
        try
        {
            CngKey.Exists(KeyNamePrefix + "probe", new CngProvider(ProviderName));
            return null;
        }
        catch (CryptographicException ex)
        {
            return $"No usable TPM: {ex.Message}";
        }
    }

    [SupportedOSPlatform("windows")]
    private DeviceKeyResult<DeviceKeyInfo> Create(DeviceKeyId id, DeviceKeyAccess access)
    {
        CngProvider provider = new CngProvider(ProviderName);
        FileInfo file = RecordFileOf(id);
        lock (_sync)
        {
            try
            {
                if (CngKey.Exists(KeyNameOf(id), provider) || file.Exists)
                {
                    return AlreadyExists(id);
                }
            }
            catch (CryptographicException ex)
            {
                return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM could not be asked about the key: {ex.Message}");
            }
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
                // Another store instance or process may have created the same key between the check and the create.
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
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException || ex is CryptographicException || ex is ArgumentException)
                {
                    string rollback = DeleteQuietly(key);
                    return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The key's record could not be written, so the key was not kept: {ex.Message}{rollback}");
                }
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static DeviceKeyResult<DeviceKeySignature> Sign(DeviceKeyId id, byte[] data)
    {
        CngProvider provider = new CngProvider(ProviderName);
        if (!CngKey.Exists(KeyNameOf(id), provider))
        {
            return DeviceKeyRequests.NotFound<DeviceKeySignature>(id);
        }
        try
        {
            using CngKey key = CngKey.Open(KeyNameOf(id), provider);
            using ECDsaCng ecdsa = new ECDsaCng(key);
            byte[] der = ecdsa.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            return DeviceKeyResult<DeviceKeySignature>.Success(new DeviceKeySignature { Id = id, Der = der });
        }
        catch (Exception ex) when (ex is CryptographicException || ex is ArgumentException)
        {
            // ArgumentException: a key under this name that is not an ECDSA key.
            return DeviceKeyResult<DeviceKeySignature>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM did not sign: {ex.Message}");
        }
    }

    [SupportedOSPlatform("windows")]
    private DeviceKeyResult<DeviceKeyInfo> Describe(DeviceKeyId id)
    {
        CngProvider provider = new CngProvider(ProviderName);
        FileInfo file = RecordFileOf(id);
        lock (_sync)
        {
            try
            {
                if (!CngKey.Exists(KeyNameOf(id), provider))
                {
                    // A read never deletes: a stale record stays until DeleteAsync removes it.
                    return DeviceKeyRequests.NotFound<DeviceKeyInfo>(id);
                }
                DeviceKeyRecord? record = ReadRecord(file);
                if (record == null)
                {
                    return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The record for key '{id.Alias}' in scope '{id.Scope}' is missing or unreadable.");
                }
                if (!Enum.IsDefined(record.Access) || !Supported.Contains(record.Access))
                {
                    return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The record for key '{id.Alias}' in scope '{id.Scope}' names access '{record.Access}', which this store does not create.");
                }
                using CngKey key = CngKey.Open(KeyNameOf(id), provider);
                using ECDsaCng ecdsa = new ECDsaCng(key);
                return DeviceKeyResult<DeviceKeyInfo>.Success(CanonicalSpki.Describe(id, ecdsa.ExportSubjectPublicKeyInfo(), record.CreatedUtc, DeviceKeyProtection.Hardware, record.Access));
            }
            catch (Exception ex) when (ex is CryptographicException || ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException)
            {
                return DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The key could not be read: {ex.Message}");
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private DeviceKeyResult<bool> Delete(DeviceKeyId id)
    {
        CngProvider provider = new CngProvider(ProviderName);
        FileInfo file = RecordFileOf(id);
        lock (_sync)
        {
            bool existed = false;
            try
            {
                if (CngKey.Exists(KeyNameOf(id), provider))
                {
                    using CngKey key = CngKey.Open(KeyNameOf(id), provider);
                    key.Delete();
                    existed = true;
                }
            }
            catch (CryptographicException ex)
            {
                return DeviceKeyResult<bool>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The TPM did not delete the key: {ex.Message}");
            }
            try
            {
                if (file.Exists)
                {
                    file.Delete();
                }
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                return DeviceKeyResult<bool>.Failure(DeviceKeyErrorCategory.PlatformFailure, $"The key's record could not be removed: {ex.Message}");
            }
            return DeviceKeyResult<bool>.Success(existed);
        }
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
    /// Writes a record to a temporary file beside it and moves it into place, so a crash never leaves a partial record.
    /// </summary>
    private static void WriteRecord(FileInfo file, DeviceKeyRecord record)
    {
        DirectoryInfo directory = file.Directory ?? throw new IOException($"'{file.FullName}' has no directory.");
        directory.Create();
        string temporary = Path.Combine(directory.FullName, $".{Guid.NewGuid():N}.tmp");
        try
        {
            File.WriteAllText(temporary, record.ToJson());
            File.Move(temporary, file.FullName, false);
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
    /// Reads a record, or null when it is missing, empty or not a record.
    /// </summary>
    private static DeviceKeyRecord? ReadRecord(FileInfo file)
    {
        if (!file.Exists)
        {
            return null;
        }
        string json = File.ReadAllText(file.FullName);
        if (string.IsNullOrWhiteSpace(json) || !json.TryFromJson<DeviceKeyRecord>(out DeviceKeyRecord record))
        {
            return null;
        }
        return record;
    }

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

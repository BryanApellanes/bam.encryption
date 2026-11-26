using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Bam.Encryption.DeviceKeys;

/// <summary>
/// A device-key store that keeps keys in process memory and forgets them when disposed. Protection is
/// <see cref="DeviceKeyProtection.Software"/> and the only access policy is <see cref="DeviceKeyAccess.None"/>: there
/// is no prompt to enforce anything stronger. Callers must opt in with
/// <c>MinimumProtection = DeviceKeyProtection.Software</c>. Use it for tests and for demo pages scoped to a single
/// visit, never to hold a key someone depends on.
/// </summary>
public sealed class InMemoryDeviceKeyStore : IDeviceKeyStore, IDisposable
{
    private static readonly IReadOnlyList<DeviceKeyAccess> Supported = Array.AsReadOnly(new[] { DeviceKeyAccess.None });

    private readonly ConcurrentDictionary<DeviceKeyId, Entry> _keys = new ConcurrentDictionary<DeviceKeyId, Entry>();

    private readonly TimeProvider _clock;

    private bool _disposed;

    /// <summary>
    /// Creates an empty store that uses the system clock.
    /// </summary>
    public InMemoryDeviceKeyStore() : this(TimeProvider.System)
    {
    }

    /// <summary>
    /// Creates an empty store.
    /// </summary>
    /// <param name="clock">The clock that stamps <see cref="DeviceKeyInfo.CreatedUtc"/>.</param>
    public InMemoryDeviceKeyStore(TimeProvider clock)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    /// <inheritdoc />
    public Task<DeviceKeyCapabilities> GetCapabilitiesAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new DeviceKeyCapabilities
        {
            IsSupported = !_disposed,
            Protection = DeviceKeyProtection.Software,
            SupportedAccess = Supported,
            SupportsAttestation = false,
            Reason = _disposed ? "The store has been disposed." : null,
        });
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<DeviceKeyInfo>> CreateAsync(DeviceKeyCreateRequest request, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<DeviceKeyInfo>? refused = DeviceKeyRequests.CheckCreate<DeviceKeyInfo>(request, Supported, DeviceKeyProtection.Software, cancellationToken, _disposed);
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        DeviceKeyId id = new DeviceKeyId(request.Scope, request.Alias ?? DeviceKeyId.NewAlias());
        ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        DeviceKeyInfo info = CanonicalSpki.Describe(id, key.ExportSubjectPublicKeyInfo(), _clock.GetUtcNow(), DeviceKeyProtection.Software, request.Access);
        if (!_keys.TryAdd(id, new Entry(key, info)))
        {
            key.Dispose();
            return Task.FromResult(DeviceKeyResult<DeviceKeyInfo>.Failure(DeviceKeyErrorCategory.AlreadyExists, $"A key '{id.Alias}' already exists in scope '{id.Scope}'."));
        }
        return Task.FromResult(DeviceKeyResult<DeviceKeyInfo>.Success(info));
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<DeviceKeySignature>> SignAsync(DeviceKeyId id, byte[] data, string? promptReason = null, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<DeviceKeySignature>? refused = DeviceKeyRequests.CheckSign<DeviceKeySignature>(id, data, cancellationToken, _disposed);
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        if (!_keys.TryGetValue(id, out Entry? entry))
        {
            return Task.FromResult(DeviceKeyRequests.NotFound<DeviceKeySignature>(id));
        }
        try
        {
            byte[] der = entry.Key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            return Task.FromResult(DeviceKeyResult<DeviceKeySignature>.Success(new DeviceKeySignature { Id = id, Der = der }));
        }
        catch (ObjectDisposedException)
        {
            // deleted while this call was signing
            return Task.FromResult(DeviceKeyRequests.NotFound<DeviceKeySignature>(id));
        }
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<DeviceKeyInfo>> GetAsync(DeviceKeyId id, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<DeviceKeyInfo>? refused = DeviceKeyRequests.CheckId<DeviceKeyInfo>(id, cancellationToken, _disposed);
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        return Task.FromResult(_keys.TryGetValue(id, out Entry? entry)
            ? DeviceKeyResult<DeviceKeyInfo>.Success(entry.Info)
            : DeviceKeyRequests.NotFound<DeviceKeyInfo>(id));
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>> ListAsync(string scope, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>? refused = DeviceKeyRequests.CheckScope<IReadOnlyList<DeviceKeyInfo>>(scope, cancellationToken, _disposed);
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        List<DeviceKeyInfo> keys = _keys.Values
            .Select(entry => entry.Info)
            .Where(info => info.Id.Scope.Equals(scope, StringComparison.Ordinal))
            .OrderBy(info => info.CreatedUtc)
            .ThenBy(info => info.Id.Alias, StringComparer.Ordinal)
            .ToList();
        return Task.FromResult(DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>.Success(keys));
    }

    /// <inheritdoc />
    public Task<DeviceKeyResult<bool>> DeleteAsync(DeviceKeyId id, CancellationToken cancellationToken = default)
    {
        DeviceKeyResult<bool>? refused = DeviceKeyRequests.CheckId<bool>(id, cancellationToken, _disposed);
        if (refused != null)
        {
            return Task.FromResult(refused);
        }
        if (_keys.TryRemove(id, out Entry? entry))
        {
            entry.Key.Dispose();
            return Task.FromResult(DeviceKeyResult<bool>.Success(true));
        }
        return Task.FromResult(DeviceKeyResult<bool>.Success(false));
    }

    /// <summary>
    /// Forgets every key.
    /// </summary>
    public void Dispose()
    {
        _disposed = true;
        foreach (DeviceKeyId id in _keys.Keys.ToList())
        {
            if (_keys.TryRemove(id, out Entry? entry))
            {
                entry.Key.Dispose();
            }
        }
    }

    private sealed record Entry(ECDsa Key, DeviceKeyInfo Info);
}

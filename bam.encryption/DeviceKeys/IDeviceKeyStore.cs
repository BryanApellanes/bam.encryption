namespace Bam.Encryption.DeviceKeys;

/// <summary>
/// Holds device keys: ECDSA P-256 signing keys that never leave the device they were created on. A store creates a
/// key, signs with it, describes it and deletes it; nothing in this contract exports a private key.
/// </summary>
/// <remarks>
/// <para>
/// Every implementation (in-memory and Windows TPM here, an encrypted software store in bam.storage.encryption,
/// Android Keystore and Apple Secure Enclave/Keychain in bam.maui) follows the same rules:
/// </para>
/// <list type="bullet">
/// <item>Every call is asynchronous and takes a <see cref="CancellationToken"/>. Signing may show an operating-system
/// prompt; a cancelled token or a dismissed prompt ends as <see cref="DeviceKeyErrorCategory.Cancelled"/>, never as
/// an exception.</item>
/// <item>The only algorithm is <see cref="DeviceKeyAlgorithm"/>: ECDSA on P-256 with SHA-256. Signing takes the data,
/// hashes it inside, and returns a DER (X9.62) signature.</item>
/// <item>A key's <see cref="DeviceKeyAccess"/> is fixed when it is created. A store that cannot enforce the requested
/// access refuses with <see cref="DeviceKeyErrorCategory.NotSupported"/> rather than creating a weaker key.</item>
/// <item><see cref="DeviceKeyInfo.Protection"/> reports what actually protects the key, never more.</item>
/// <item>Failures are reported as a <see cref="DeviceKeyErrorCategory"/>, so callers act on the category, not on a
/// message.</item>
/// </list>
/// <para>Designed in BryanApellanes/threeheadz-tracker#39 (whatit.is device-key front door).</para>
/// </remarks>
public interface IDeviceKeyStore
{
    /// <summary>
    /// Describes what this store can do on this machine. Never prompts and never creates a key.
    /// </summary>
    /// <param name="cancellationToken">Cancels the probe.</param>
    /// <returns>The store's capabilities.</returns>
    Task<DeviceKeyCapabilities> GetCapabilitiesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new device key.
    /// </summary>
    /// <param name="request">The scope, optional alias and access policy for the key.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The new key's description, or why it could not be created.</returns>
    Task<DeviceKeyResult<DeviceKeyInfo>> CreateAsync(DeviceKeyCreateRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Signs <paramref name="data"/> with the key. The data is hashed with SHA-256 inside the store; pass the payload
    /// itself, never a digest.
    /// </summary>
    /// <param name="id">The key to sign with.</param>
    /// <param name="data">The bytes to sign.</param>
    /// <param name="promptReason">The text an operating-system prompt shows, when the key's access needs one. The
    /// calling app supplies it.</param>
    /// <param name="cancellationToken">Cancels the operation, including a prompt that is showing.</param>
    /// <returns>The DER signature, or why the key did not sign.</returns>
    Task<DeviceKeyResult<DeviceKeySignature>> SignAsync(DeviceKeyId id, byte[] data, string? promptReason = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Describes one key.
    /// </summary>
    /// <param name="id">The key to describe.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The key's description, or <see cref="DeviceKeyErrorCategory.KeyNotFound"/>.</returns>
    Task<DeviceKeyResult<DeviceKeyInfo>> GetAsync(DeviceKeyId id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lists the keys held for one scope, oldest first.
    /// </summary>
    /// <param name="scope">The scope (an account or derived handle) whose keys to list.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The keys in the scope; an empty list when there are none.</returns>
    Task<DeviceKeyResult<IReadOnlyList<DeviceKeyInfo>>> ListAsync(string scope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a key. Idempotent: deleting a key that does not exist succeeds.
    /// </summary>
    /// <param name="id">The key to delete.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>True when a key was deleted, false when there was none.</returns>
    Task<DeviceKeyResult<bool>> DeleteAsync(DeviceKeyId id, CancellationToken cancellationToken = default);
}

using System.Text.RegularExpressions;

namespace Bam.Encryption.DeviceKeys;

/// <summary>
/// The one algorithm device keys use. There is no choice on purpose: Secure Enclave and StrongBox support only P-256,
/// and a contract that offered other curves would invite a store to silently not honour them.
/// </summary>
public static class DeviceKeyAlgorithm
{
    /// <summary>The curve: NIST P-256 (secp256r1, prime256v1).</summary>
    public const string Curve = "P-256";

    /// <summary>The curve's object identifier.</summary>
    public const string CurveOid = "1.2.840.10045.3.1.7";

    /// <summary>The signature algorithm, in the name bam.protocol's verifiers use. Signatures are DER (X9.62).</summary>
    public const string SignatureAlgorithm = "SHA256WITHECDSA";
}

/// <summary>
/// Names one device key: the scope it belongs to (an account or derived handle) and its alias within that scope.
/// Both use the characters <c>a-z</c>, <c>0-9</c>, <c>.</c>, <c>_</c> and <c>-</c>, start with a letter or digit,
/// and are at most 64 characters.
/// </summary>
/// <param name="Scope">The scope the key belongs to.</param>
/// <param name="Alias">The key's alias within the scope.</param>
public sealed record DeviceKeyId(string Scope, string Alias)
{
    private static readonly Regex NamePattern = new Regex("^[a-z0-9][a-z0-9._-]{0,63}$", RegexOptions.CultureInvariant);

    /// <summary>
    /// Whether <paramref name="value"/> is a valid scope or alias.
    /// </summary>
    /// <param name="value">The candidate.</param>
    /// <returns>True when it matches the allowed form.</returns>
    public static bool IsValidName(string? value)
    {
        return value != null && NamePattern.IsMatch(value);
    }

    /// <summary>
    /// Whether both parts of this id are valid.
    /// </summary>
    public bool IsValid => IsValidName(Scope) && IsValidName(Alias);

    /// <summary>
    /// Returns a new random alias: 16 characters of lowercase base32.
    /// </summary>
    /// <returns>The alias.</returns>
    public static string NewAlias()
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        byte[] random = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        char[] alias = new char[16];
        for (int i = 0; i < alias.Length; i++)
        {
            alias[i] = alphabet[random[i] & 31];
        }
        return new string(alias);
    }
}

/// <summary>
/// What to create.
/// </summary>
public sealed class DeviceKeyCreateRequest
{
    /// <summary>The scope (an account or derived handle) the key belongs to. Required.</summary>
    public string Scope { get; set; } = string.Empty;

    /// <summary>The alias. When null the store generates one with <see cref="DeviceKeyId.NewAlias"/>.</summary>
    public string? Alias { get; set; }

    /// <summary>What a person must do before the key signs. Fixed for the key's life.</summary>
    public DeviceKeyAccess Access { get; set; } = DeviceKeyAccess.None;

    /// <summary>The weakest protection the caller accepts. A store that cannot meet it refuses with
    /// <see cref="DeviceKeyErrorCategory.NotSupported"/>. The default, <see cref="DeviceKeyProtection.Hardware"/>,
    /// means a caller never gets a software key by accident: <see cref="DeviceKeyProtection.Software"/> is the
    /// explicit opt-in, and <see cref="DeviceKeyProtection.StrongBox"/> requires a separate secure element. A store
    /// gives the best protection it can at or above the minimum and reports it in
    /// <see cref="DeviceKeyInfo.Protection"/>.</summary>
    public DeviceKeyProtection MinimumProtection { get; set; } = DeviceKeyProtection.Hardware;

    /// <summary>A server-issued nonce to bind into the key's attestation, or null for none. Platforms that attest
    /// (Android) only do so when the challenge is given at create time. A store that cannot attest ignores it and
    /// returns a null <see cref="DeviceKeyInfo.Attestation"/>.</summary>
    public byte[]? AttestationChallenge { get; set; }
}

/// <summary>
/// A platform's statement that a key was made in its secure hardware.
/// </summary>
public sealed class DeviceKeyAttestation
{
    /// <summary>The Android key-attestation format.</summary>
    public const string AndroidKey = "android-key";

    /// <summary>What kind of attestation this is, which tells a verifier how to check it: <see cref="AndroidKey"/>
    /// today.</summary>
    public string Format { get; init; } = string.Empty;

    /// <summary>The certificates, DER, leaf first.</summary>
    public IReadOnlyList<byte[]> Certificates { get; init; } = Array.Empty<byte[]>();
}

/// <summary>
/// Describes a device key. Holds only public information.
/// </summary>
public sealed class DeviceKeyInfo
{
    /// <summary>The key's scope and alias.</summary>
    public DeviceKeyId Id { get; init; } = new DeviceKeyId(string.Empty, string.Empty);

    /// <summary>The public key as canonical DER SubjectPublicKeyInfo (named curve, uncompressed point).</summary>
    public byte[] PublicKeySpki { get; init; } = Array.Empty<byte>();

    /// <summary>The key's fingerprint: SHA-256 of <see cref="PublicKeySpki"/>, 64 lowercase hex characters.</summary>
    public string Fingerprint { get; init; } = string.Empty;

    /// <summary>When the key was created, in UTC, to the second.</summary>
    public DateTimeOffset CreatedUtc { get; init; }

    /// <summary>What actually protects the private key.</summary>
    public DeviceKeyProtection Protection { get; init; }

    /// <summary>What a person must do before the key signs.</summary>
    public DeviceKeyAccess Access { get; init; }

    /// <summary>The platform's attestation of the key, or null when it cannot attest one (Apple, and Windows for now)
    /// or no <see cref="DeviceKeyCreateRequest.AttestationChallenge"/> was given. Nothing requires it.</summary>
    public DeviceKeyAttestation? Attestation { get; init; }
}

/// <summary>
/// A device key's signature.
/// </summary>
public sealed class DeviceKeySignature
{
    /// <summary>The key that signed.</summary>
    public DeviceKeyId Id { get; init; } = new DeviceKeyId(string.Empty, string.Empty);

    /// <summary>The DER (X9.62) ECDSA signature over the SHA-256 of the data.</summary>
    public byte[] Der { get; init; } = Array.Empty<byte>();

    /// <summary>The algorithm, always <see cref="DeviceKeyAlgorithm.SignatureAlgorithm"/>.</summary>
    public string Algorithm { get; init; } = DeviceKeyAlgorithm.SignatureAlgorithm;
}

/// <summary>
/// What a store can do on this machine.
/// </summary>
public sealed class DeviceKeyCapabilities
{
    /// <summary>Whether the store can create and use keys here at all.</summary>
    public bool IsSupported { get; init; }

    /// <summary>The protection keys created here get.</summary>
    public DeviceKeyProtection Protection { get; init; }

    /// <summary>The access policies this store can enforce.</summary>
    public IReadOnlyList<DeviceKeyAccess> SupportedAccess { get; init; } = Array.Empty<DeviceKeyAccess>();

    /// <summary>Whether keys created here come with an attestation chain.</summary>
    public bool SupportsAttestation { get; init; }

    /// <summary>Why the store is not supported, when it is not.</summary>
    public string? Reason { get; init; }
}

/// <summary>
/// Why an operation failed.
/// </summary>
/// <param name="Category">What kind of failure, for the caller to act on.</param>
/// <param name="Message">A description for people.</param>
public sealed record DeviceKeyError(DeviceKeyErrorCategory Category, string Message);

/// <summary>
/// The outcome of a device-key operation: a value, or an error.
/// </summary>
/// <typeparam name="T">The value's type.</typeparam>
public sealed class DeviceKeyResult<T>
{
    private DeviceKeyResult(bool succeeded, T? value, DeviceKeyError? error)
    {
        Succeeded = succeeded;
        Value = value;
        Error = error;
    }

    /// <summary>Whether the operation succeeded.</summary>
    public bool Succeeded { get; }

    /// <summary>The value, when the operation succeeded.</summary>
    public T? Value { get; }

    /// <summary>Why it failed, when it did.</summary>
    public DeviceKeyError? Error { get; }

    /// <summary>A successful outcome.</summary>
    /// <param name="value">The value.</param>
    /// <returns>The outcome.</returns>
    public static DeviceKeyResult<T> Success(T value)
    {
        return new DeviceKeyResult<T>(true, value, null);
    }

    /// <summary>A failed outcome.</summary>
    /// <param name="category">What kind of failure.</param>
    /// <param name="message">A description for people.</param>
    /// <returns>The outcome.</returns>
    public static DeviceKeyResult<T> Failure(DeviceKeyErrorCategory category, string message)
    {
        return new DeviceKeyResult<T>(false, default, new DeviceKeyError(category, message));
    }
}

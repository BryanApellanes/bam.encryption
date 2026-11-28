namespace Bam.Encryption;

/// <summary>
/// What <see cref="AeadKey.Open"/> found.
/// </summary>
public enum AeadOpenStatus
{
    /// <summary>The tag verified; the plaintext is available.</summary>
    Opened,

    /// <summary>The tag did not verify. The ciphertext, tag, nonce, key or associated data differ from the ones
    /// sealed.</summary>
    Tampered,

    /// <summary>The input cannot be sealed data: a nonce of the wrong length, or data shorter than a tag.</summary>
    Malformed,
}

/// <summary>
/// The result of <see cref="AeadKey.Open"/>. <see cref="Plaintext"/> is set only when <see cref="Status"/> is
/// <see cref="AeadOpenStatus.Opened"/>.
/// </summary>
public sealed class AeadOpenResult
{
    private AeadOpenResult(AeadOpenStatus status, byte[]? plaintext, string reason)
    {
        Status = status;
        Plaintext = plaintext;
        Reason = reason;
    }

    /// <summary>What was found.</summary>
    public AeadOpenStatus Status { get; }

    /// <summary>The plaintext when opened, otherwise null.</summary>
    public byte[]? Plaintext { get; }

    /// <summary>Why it was refused, or an empty string when opened.</summary>
    public string Reason { get; }

    /// <summary>True when <see cref="Status"/> is <see cref="AeadOpenStatus.Opened"/>.</summary>
    public bool Succeeded => Status == AeadOpenStatus.Opened;

    internal static AeadOpenResult Opened(byte[] plaintext) => new AeadOpenResult(AeadOpenStatus.Opened, plaintext, string.Empty);

    internal static AeadOpenResult Tampered() => new AeadOpenResult(AeadOpenStatus.Tampered, null, "The tag does not verify.");

    internal static AeadOpenResult Malformed(string reason) => new AeadOpenResult(AeadOpenStatus.Malformed, null, reason);
}

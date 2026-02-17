namespace Bam.Encryption;

/// <summary>
/// Represents a digital signature containing the raw signature bytes, signed data, and algorithm used.
/// </summary>
public class Signature : ISignature
{
    /// <inheritdoc />
    public byte[] SignatureBytes { get; set; } = null!;

    /// <inheritdoc />
    public string SignatureBase64 { get => SignatureBytes.ToBase64(); }

    /// <inheritdoc />
    public string Data { get; set; } = null!;

    /// <inheritdoc />
    public string Algorithm { get; set; } = null!;
}
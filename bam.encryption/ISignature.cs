namespace Bam.Encryption;

/// <summary>
/// Represents a digital signature including the signature bytes, the signed data, and the algorithm used.
/// </summary>
public interface ISignature
{
    /// <summary>
    /// Gets the raw signature bytes.
    /// </summary>
    byte[] SignatureBytes { get; }

    /// <summary>
    /// Gets the Base64-encoded representation of the signature bytes.
    /// </summary>
    string SignatureBase64 { get; }

    /// <summary>
    /// Gets the original data that was signed.
    /// </summary>
    string Data { get; }

    /// <summary>
    /// Gets the algorithm used to create the signature.
    /// </summary>
    string Algorithm { get; }
}
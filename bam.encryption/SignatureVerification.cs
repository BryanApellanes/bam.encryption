namespace Bam.Encryption;

/// <summary>
/// Represents the result of a digital signature verification, including the signature, success status, and issuer's public key.
/// </summary>
public class SignatureVerification : ISignatureVerification
{
    /// <inheritdoc />
    public ISignature Signature { get; set; } = null!;

    /// <inheritdoc />
    public bool Success { get; set; }

    /// <inheritdoc />
    public string Message { get; set; } = null!;

    /// <inheritdoc />
    public IPublicKey IssuerPublicKey { get; set; } = null!;
}
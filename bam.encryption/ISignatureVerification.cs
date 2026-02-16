namespace Bam.Encryption;

/// <summary>
/// Represents the result of verifying a digital signature, including success status and the issuer's public key.
/// </summary>
public interface ISignatureVerification
{
    /// <summary>
    /// Gets or sets the signature that was verified.
    /// </summary>
    ISignature Signature { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the signature verification succeeded.
    /// </summary>
    bool Success { get; set; }

    /// <summary>
    /// Gets or sets a message describing the verification result.
    /// </summary>
    string Message { get; set; }

    /// <summary>
    /// Gets or sets the public key of the signature issuer used for verification.
    /// </summary>
    IPublicKey IssuerPublicKey { get; set; }
}
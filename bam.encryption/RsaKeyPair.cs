namespace Bam.Encryption;

/// <summary>
/// Represents an RSA key pair that wraps an <see cref="RsaPublicPrivateKeyPair"/> and provides public/private key access.
/// </summary>
public class RsaKeyPair : KeyPair
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RsaKeyPair"/> class by generating a new RSA key pair.
    /// </summary>
    public RsaKeyPair() : this(new RsaPublicPrivateKeyPair())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RsaKeyPair"/> class from an existing RSA public-private key pair.
    /// </summary>
    /// <param name="rsaKeyPair">The RSA public-private key pair to wrap.</param>
    public RsaKeyPair(RsaPublicPrivateKeyPair rsaKeyPair) : base(rsaKeyPair)
    {
        this.Value = rsaKeyPair;
    }

    /// <summary>
    /// Gets or sets the underlying RSA public-private key pair.
    /// </summary>
    public RsaPublicPrivateKeyPair Value { get; set; }
}
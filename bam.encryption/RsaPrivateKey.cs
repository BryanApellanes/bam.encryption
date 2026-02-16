using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

/// <summary>
/// Represents an RSA private key with PEM encoding and disposable semantics.
/// </summary>
public class RsaPrivateKey : PrivateKey
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RsaPrivateKey"/> class by generating a new RSA key pair.
    /// </summary>
    public RsaPrivateKey() : base(new RsaPublicPrivateKeyPair())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RsaPrivateKey"/> class from an existing RSA key pair.
    /// </summary>
    /// <param name="rsaKeyPair">The RSA key pair to extract the private key from.</param>
    public RsaPrivateKey(RsaPublicPrivateKeyPair rsaKeyPair) : base(rsaKeyPair)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RsaPrivateKey"/> class from an asymmetric key parameter.
    /// </summary>
    /// <param name="privateKey">The asymmetric key parameter representing the private key.</param>
    public RsaPrivateKey(AsymmetricKeyParameter privateKey) : base(privateKey)
    {
    }
}
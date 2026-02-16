using Bam.encryption;
using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

/// <summary>
/// Abstract base class for cryptographic key pairs that wraps either RSA or ECC key pairs.
/// </summary>
public abstract class KeyPair : DisposablePem, IKeyPair
{
    /// <summary>
    /// Initializes a new instance of the <see cref="KeyPair"/> class from an RSA key pair.
    /// </summary>
    /// <param name="rsaKeyPair">The RSA public-private key pair.</param>
    public KeyPair(RsaPublicPrivateKeyPair rsaKeyPair)
    {
        this.Pem = rsaKeyPair.Pem;
        this.PublicPem = rsaKeyPair.PublicKeyPem;
        this.PublicKey = new RsaPublicKey(rsaKeyPair.PublicKeyPem);
        this.PrivateKey = new RsaPrivateKey(rsaKeyPair.AsymmetricCipherKeyPair.Private);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeyPair"/> class from an ECC key pair.
    /// </summary>
    /// <param name="eccKeyPair">The ECC public-private key pair.</param>
    public KeyPair(EccPublicPrivateKeyPair eccKeyPair)
    {
        this.Pem = eccKeyPair.Pem;
        this.PublicPem = eccKeyPair.PublicKeyPem;
        this.PublicKey = new EccPublicKey(eccKeyPair.AsymmetricCipherKeyPair.Public);
        this.PrivateKey = new EccPrivateKey(eccKeyPair.AsymmetricCipherKeyPair.Private);
    }

    /// <inheritdoc />
    public string PublicPem { get; protected set; }

    /// <inheritdoc />
    public IPublicKey PublicKey { get; }

    /// <inheritdoc />
    public IPrivateKey PrivateKey { get; }
}
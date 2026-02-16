using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

/// <summary>
/// Abstract base class for public keys that provides PEM encoding from various key pair sources.
/// </summary>
public abstract class PublicKey : IPublicKey
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKey"/> class from an RSA key pair.
    /// </summary>
    /// <param name="rsaKeyPair">The RSA key pair to extract the public key from.</param>
    public PublicKey(RsaPublicPrivateKeyPair rsaKeyPair): this(rsaKeyPair.AsymmetricCipherKeyPair.Public)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKey"/> class from an ECC key pair.
    /// </summary>
    /// <param name="eccKeyPair">The ECC key pair to extract the public key from.</param>
    public PublicKey(EccPublicPrivateKeyPair eccKeyPair) : this(eccKeyPair.AsymmetricCipherKeyPair.Public)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PublicKey"/> class from an asymmetric key parameter.
    /// </summary>
    /// <param name="key">The asymmetric key parameter representing the public key.</param>
    public PublicKey(AsymmetricKeyParameter key)
    {
        this.Value = key;
    }

    /// <inheritdoc />
    public virtual string Pem => Value.ToPem();

    /// <inheritdoc />
    public AsymmetricKeyParameter Value { get; }
}
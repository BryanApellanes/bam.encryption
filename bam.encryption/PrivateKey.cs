using Org.BouncyCastle.Crypto;
using System.Text;

namespace Bam.Encryption;

/// <summary>
/// Abstract base class for private keys that provides PEM encoding and disposable semantics.
/// </summary>
public abstract class PrivateKey : DisposablePem, IPrivateKey
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKey"/> class from an RSA key pair.
    /// </summary>
    /// <param name="rsaKeyPair">The RSA key pair to extract the private key from.</param>
    public PrivateKey(RsaPublicPrivateKeyPair rsaKeyPair): this(rsaKeyPair.AsymmetricCipherKeyPair.Private)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKey"/> class from an ECC key pair.
    /// </summary>
    /// <param name="eccKeyPair">The ECC key pair to extract the private key from.</param>
    public PrivateKey(EccPublicPrivateKeyPair eccKeyPair) : this(eccKeyPair.AsymmetricCipherKeyPair.Private)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKey"/> class from an asymmetric key parameter.
    /// </summary>
    /// <param name="key">The asymmetric key parameter representing the private key.</param>
    public PrivateKey(AsymmetricKeyParameter key)
    {
        this.Value = key;
        this.Pem = Value.ToPem(Encoding.UTF8);
    }

    /// <inheritdoc />
    public AsymmetricKeyParameter Value { get; }
}
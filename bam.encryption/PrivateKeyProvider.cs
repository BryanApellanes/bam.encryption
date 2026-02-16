using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Bam.Encryption;

/// <summary>
/// Provides a private key from various cryptographic key pair sources.
/// </summary>
public class PrivateKeyProvider : IPrivateKeyProvider
{
    private AsymmetricKeyParameter _privateKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyProvider"/> class with the specified asymmetric key parameter.
    /// </summary>
    /// <param name="privateKey">The asymmetric private key parameter.</param>
    public PrivateKeyProvider(AsymmetricKeyParameter privateKey)
    {
        this._privateKey = privateKey;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyProvider"/> class from an RSA key source.
    /// </summary>
    /// <param name="privateKey">The RSA key source to extract the private key from.</param>
    public PrivateKeyProvider(IRsaKeySource privateKey)
    {
        this._privateKey = privateKey.GetRsaKey().AsymmetricCipherKeyPair.Private;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyProvider"/> class from an RSA key pair.
    /// </summary>
    /// <param name="privateKeyPair">The RSA public-private key pair to extract the private key from.</param>
    public PrivateKeyProvider(RsaPublicPrivateKeyPair privateKeyPair)
    {
        this._privateKey = privateKeyPair.AsymmetricCipherKeyPair.Private;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PrivateKeyProvider"/> class from an ECC key pair.
    /// </summary>
    /// <param name="eccKeyPair">The ECC public-private key pair to extract the private key from.</param>
    public PrivateKeyProvider(EccPublicPrivateKeyPair eccKeyPair)
    {
        this._privateKey = eccKeyPair.AsymmetricCipherKeyPair.Private;
    }

    /// <inheritdoc />
    public AsymmetricKeyParameter GetPrivateKey()
    {
        return this._privateKey;
    }
}
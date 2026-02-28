using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

/// <summary>
/// Represents an Elliptic Curve Cryptography (ECC) private key.
/// </summary>
public class EccPrivateKey : PrivateKey
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EccPrivateKey"/> class, generating a new ECC key pair.
    /// </summary>
    public EccPrivateKey() : base(new EccPublicPrivateKeyPair())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EccPrivateKey"/> class from an existing ECC key pair.
    /// </summary>
    /// <param name="eccKeyPair">The ECC public/private key pair to extract the private key from.</param>
    public EccPrivateKey(EccPublicPrivateKeyPair eccKeyPair) : base(eccKeyPair)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EccPrivateKey"/> class from a BouncyCastle asymmetric key parameter.
    /// </summary>
    /// <param name="privateKey">The asymmetric key parameter representing the private key.</param>
    public EccPrivateKey(AsymmetricKeyParameter privateKey) : base(privateKey)
    {
    }

    public override ISignature Sign(string data)
    {
        return new EccSignatureProvider().Sign(new PrivateKeyProvider(Value), data, "SHA256WITHECDSA");
    }

    public override ISignature Sign(byte[] data)
    {
        return Sign(Convert.ToBase64String(data));
    }
}
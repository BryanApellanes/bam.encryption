using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Bam.Encryption;

/// <summary>
/// Represents an Elliptic Curve Cryptography (ECC) public key with PEM string conversion support.
/// </summary>
public class EccPublicKey : PublicKey
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EccPublicKey"/> class, generating a new ECC key pair.
    /// </summary>
    public EccPublicKey() : base(new EccPublicPrivateKeyPair())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EccPublicKey"/> class from a PEM-encoded public key string.
    /// </summary>
    /// <param name="eccPublicKeyPem">The PEM-encoded ECC public key string.</param>
    public EccPublicKey(string eccPublicKeyPem) : this(eccPublicKeyPem.PemToKey())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EccPublicKey"/> class from an existing ECC key pair.
    /// </summary>
    /// <param name="eccKeyPair">The ECC public/private key pair to extract the public key from.</param>
    public EccPublicKey(EccPublicPrivateKeyPair eccKeyPair) : base(eccKeyPair)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EccPublicKey"/> class from a BouncyCastle asymmetric key parameter.
    /// </summary>
    /// <param name="key">The asymmetric key parameter representing the public key.</param>
    public EccPublicKey(AsymmetricKeyParameter key) : base(key)
    {
    }

    /// <summary>
    /// Gets or sets the EC public key parameters.
    /// </summary>
    public new ECPublicKeyParameters Value { get; set; } = null!;

    /// <summary>
    /// Implicitly converts an <see cref="EccPublicKey"/> to its PEM-encoded string representation.
    /// </summary>
    /// <param name="eccPublicKey">The ECC public key to convert.</param>
    public static implicit operator string(EccPublicKey eccPublicKey)
    {
        return eccPublicKey.Value.ToPem();
    }
}
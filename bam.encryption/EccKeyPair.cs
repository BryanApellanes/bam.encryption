namespace Bam.Encryption;

/// <summary>
/// Represents an Elliptic Curve Cryptography (ECC) key pair with support for shared AES key derivation via ECDH.
/// </summary>
public class EccKeyPair : KeyPair
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EccKeyPair"/> class, generating a new ECC key pair.
    /// </summary>
    public EccKeyPair() : this(new EccPublicPrivateKeyPair())
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EccKeyPair"/> class from an existing ECC public/private key pair.
    /// </summary>
    /// <param name="eccKeyPair">The ECC public/private key pair to wrap.</param>
    public EccKeyPair(EccPublicPrivateKeyPair eccKeyPair) : base(eccKeyPair)
    {
        this.PublicPrivateKeyPair = eccKeyPair;
    }
    
    protected EccPublicPrivateKeyPair PublicPrivateKeyPair { get; set; }

    /// <summary>
    /// Gets an AES key using its own public key.
    /// </summary>
    /// <returns></returns>
    public AesKey GetSelfAesKey()
    {
        return PublicPrivateKeyPair.GetSharedAesKey(PublicPem);
    }

    /// <summary>
    /// Derives a shared AES key using ECDH key agreement with the specified other party's public key PEM.
    /// </summary>
    /// <param name="otherPublicPem">The PEM-encoded public key of the other party.</param>
    /// <returns>An AES key derived from the shared secret.</returns>
    public AesKey GetSharedAesKey(string otherPublicPem)
    {
        return PublicPrivateKeyPair.GetSharedAesKey(otherPublicPem);
    }
}
namespace Bam.Encryption;

public class EccKeyPair : KeyPair
{
    public EccKeyPair() : this(new EccPublicPrivateKeyPair())
    {
    }

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

    public AesKey GetSharedAesKey(string otherPublicPem)
    {
        return PublicPrivateKeyPair.GetSharedAesKey(otherPublicPem);
    }
}
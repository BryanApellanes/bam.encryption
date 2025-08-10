namespace Bam.Encryption;

public class RsaKeyPair : KeyPair
{
    public RsaKeyPair() : this(new RsaPublicPrivateKeyPair())
    {
    }

    public RsaKeyPair(RsaPublicPrivateKeyPair rsaKeyPair) : base(rsaKeyPair)
    {
        this.Value = rsaKeyPair;
    }
    
    public RsaPublicPrivateKeyPair Value { get; set; }
}
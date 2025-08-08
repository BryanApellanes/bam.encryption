namespace Bam.Encryption;

public class RsaKeyPair : KeyPair
{
    public RsaKeyPair() : base(new RsaPublicPrivateKeyPair())
    {
    }

    public RsaKeyPair(RsaPublicPrivateKeyPair rsaKeyPair) : base(rsaKeyPair)
    {
    }
}
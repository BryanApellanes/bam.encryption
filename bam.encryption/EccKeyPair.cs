namespace Bam.Encryption;

public class EccKeyPair : KeyPair
{
    public EccKeyPair() : base(new EccPublicPrivateKeyPair())
    {
    }

    public EccKeyPair(EccPublicPrivateKeyPair eccKeyPair) : base(eccKeyPair)
    {
    }
}
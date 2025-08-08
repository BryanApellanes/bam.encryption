using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public class EccPrivateKey : PrivateKey
{
    public EccPrivateKey() : base(new EccPublicPrivateKeyPair())
    {
    }

    public EccPrivateKey(EccPublicPrivateKeyPair eccKeyPair) : base(eccKeyPair)
    {
    }

    public EccPrivateKey(AsymmetricKeyParameter privateKey) : base(privateKey)
    {
    }
}
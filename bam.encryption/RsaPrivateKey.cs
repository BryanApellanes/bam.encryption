using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public class RsaPrivateKey : PrivateKey
{
    public RsaPrivateKey() : base(new RsaPublicPrivateKeyPair())
    {
    }

    public RsaPrivateKey(RsaPublicPrivateKeyPair rsaKeyPair) : base(rsaKeyPair)
    {
    }

    public RsaPrivateKey(AsymmetricKeyParameter privateKey) : base(privateKey)
    {
    }
}
using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public abstract class PrivateKey : IPrivateKey
{
    public PrivateKey(RsaPublicPrivateKeyPair rsaKeyPair): this(rsaKeyPair.AsymmetricCipherKeyPair.Private)
    {
    }

    public PrivateKey(EccPublicPrivateKeyPair eccKeyPair) : this(eccKeyPair.AsymmetricCipherKeyPair.Private)
    {
    }

    public PrivateKey(AsymmetricKeyParameter key)
    {
        this.Value = key;
    }

    public string Pem => Value.ToPem();
    public AsymmetricKeyParameter Value { get; }
}
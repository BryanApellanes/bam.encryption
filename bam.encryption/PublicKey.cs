using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public abstract class PublicKey : IPublicKey
{
    public PublicKey(RsaPublicPrivateKeyPair rsaKeyPair): this(rsaKeyPair.AsymmetricCipherKeyPair.Public)
    {
    }

    public PublicKey(EccPublicPrivateKeyPair eccKeyPair) : this(eccKeyPair.AsymmetricCipherKeyPair.Public)
    {
    }

    public PublicKey(AsymmetricKeyParameter key)
    {
        this.Value = key;
    }

    public virtual string Pem => Value.ToPem();
    
    public AsymmetricKeyParameter Value { get; }
}
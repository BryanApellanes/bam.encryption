using Org.BouncyCastle.Crypto;
using System.Text;

namespace Bam.Encryption;

public abstract class PrivateKey : DisposablePem, IPrivateKey
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
        this.Pem = Value.ToPem(Encoding.UTF8);
    }

    public AsymmetricKeyParameter Value { get; }
}
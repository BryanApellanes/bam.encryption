using Bam.encryption;
using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public abstract class KeyPair : DisposablePem, IKeyPair
{
    public KeyPair(RsaPublicPrivateKeyPair rsaKeyPair)
    {
        this.Pem = rsaKeyPair.Pem;
        this.PublicPem = rsaKeyPair.PublicKeyPem;
        this.PublicKey = new RsaPublicKey(rsaKeyPair.PublicKeyPem);
        this.PrivateKey = new RsaPrivateKey(rsaKeyPair.AsymmetricCipherKeyPair.Private);
    }

    public KeyPair(EccPublicPrivateKeyPair eccKeyPair)
    {
        this.Pem = eccKeyPair.Pem;
        this.PublicPem = eccKeyPair.PublicKeyPem;
        this.PublicKey = new EccPublicKey(eccKeyPair.AsymmetricCipherKeyPair.Public);
        this.PrivateKey = new EccPrivateKey(eccKeyPair.AsymmetricCipherKeyPair.Private);
    }
    
    public string PublicPem { get; protected set; }
    public IPublicKey PublicKey { get; }
    public IPrivateKey PrivateKey { get; }
}
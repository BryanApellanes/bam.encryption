using Bam.encryption;
using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public abstract class KeyPair : IKeyPair
{
    public KeyPair(RsaPublicPrivateKeyPair rsaKeyPair)
    {
        this.PrivatePem = rsaKeyPair.Pem;
        this.PublicPem = rsaKeyPair.PublicKeyPem;
        this.PublicKey = new RsaPublicKey(rsaKeyPair.PublicKeyPem);
        this.PrivateKey = new RsaPrivateKey(rsaKeyPair.AsymmetricCipherKeyPair.Private);
    }

    public KeyPair(EccPublicPrivateKeyPair eccKeyPair)
    {
        this.PrivatePem = eccKeyPair.Pem;
        this.PublicPem = eccKeyPair.PublicKeyPem;
        this.PublicKey = new EccPublicKey(eccKeyPair.AsymmetricCipherKeyPair.Public);
        this.PrivateKey = new EccPrivateKey(eccKeyPair.AsymmetricCipherKeyPair.Private);
    }
    
    public string PublicPem { get; protected set; }
    public string PrivatePem { get; protected set; }
    public IPublicKey PublicKey { get; }
    public IPrivateKey PrivateKey { get; }
}
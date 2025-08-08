using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Bam.Encryption;

public class PrivateKeyProvider : IPrivateKeyProvider
{
    private AsymmetricKeyParameter _privateKey;
    public PrivateKeyProvider(AsymmetricKeyParameter privateKey)
    {
        this._privateKey = privateKey;
    }

    public PrivateKeyProvider(IRsaKeySource privateKey)
    {
        this._privateKey = privateKey.GetRsaKey().AsymmetricCipherKeyPair.Private;
    }

    public PrivateKeyProvider(RsaPublicPrivateKeyPair privateKeyPair)
    {
        this._privateKey = privateKeyPair.AsymmetricCipherKeyPair.Private;
    }

    public PrivateKeyProvider(EccPublicPrivateKeyPair eccKeyPair)
    {
        this._privateKey = eccKeyPair.AsymmetricCipherKeyPair.Private;
    }
    
    public AsymmetricKeyParameter GetPrivateKey()
    {
        return this._privateKey;
    }
}
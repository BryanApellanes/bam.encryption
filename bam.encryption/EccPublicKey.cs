using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Bam.Encryption;

public class EccPublicKey : PublicKey
{
    public EccPublicKey() : base(new EccPublicPrivateKeyPair())
    {
    }

    public EccPublicKey(string eccPublicKeyPem) : this(eccPublicKeyPem.PemToKey())
    {
    }
    
    public EccPublicKey(EccPublicPrivateKeyPair eccKeyPair) : base(eccKeyPair)
    {
    }

    public EccPublicKey(AsymmetricKeyParameter key) : base(key)
    {
    }


    public new ECPublicKeyParameters Value { get; set; }

    public static implicit operator string(EccPublicKey eccPublicKey)
    {
        return eccPublicKey.Value.ToPem();
    }
}
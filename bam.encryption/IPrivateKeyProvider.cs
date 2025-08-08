using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public interface IPrivateKeyProvider
{
    AsymmetricKeyParameter GetPrivateKey();    
}
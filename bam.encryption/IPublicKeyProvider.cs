using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public interface IPublicKeyProvider
{
    AsymmetricKeyParameter GetPublicKey();
}
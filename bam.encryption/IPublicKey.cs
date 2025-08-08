using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public interface IPublicKey
{
    AsymmetricKeyParameter Value { get; }
}
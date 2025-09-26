using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public interface IPublicKey
{
    string Pem { get; }
    AsymmetricKeyParameter Value { get; }
}
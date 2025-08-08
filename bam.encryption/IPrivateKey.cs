using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public interface IPrivateKey
{
    AsymmetricKeyParameter Value { get; }
}
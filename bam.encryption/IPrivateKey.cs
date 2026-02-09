using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public interface IPrivateKey
{
    byte[] Pem { get; }
    AsymmetricKeyParameter Value { get; }
}
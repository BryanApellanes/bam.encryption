using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

public interface IPrivateKey
{
    string Pem { get; }
    AsymmetricKeyParameter Value { get; }
}
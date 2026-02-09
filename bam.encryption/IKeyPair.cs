using Bam.Encryption;
using Org.BouncyCastle.Crypto;

namespace Bam.encryption;

public interface IKeyPair
{
    string PublicPem { get; }
    byte[] Pem { get; }
    IPublicKey PublicKey { get; }
    IPrivateKey PrivateKey { get; }
}
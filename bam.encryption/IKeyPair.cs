using Bam.Encryption;
using Org.BouncyCastle.Crypto;

namespace Bam.encryption;

public interface IKeyPair
{
    string PublicPem { get; }
    string PrivatePem { get; }
    IPublicKey PublicKey { get; }
    IPrivateKey PrivateKey { get; }
}
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Bam.Encryption;

public class RsaSignatureProvider : SignatureProvider, IRsaSignatureProvider
{
    public ISignature Sign(IRsaKeySource privateKeySource, string data, string algorithm = "SHA512WITHRSA")
    {
        return Sign(new PrivateKeyProvider(privateKeySource.GetRsaKey().AsymmetricCipherKeyPair.Private), data,
            algorithm);
    }
}
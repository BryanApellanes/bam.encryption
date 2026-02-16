using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Bam.Encryption;

/// <summary>
/// Creates digital signatures using RSA keys via the BouncyCastle cryptography library.
/// </summary>
public class RsaSignatureProvider : SignatureProvider, IRsaSignatureProvider
{
    /// <inheritdoc />
    public ISignature Sign(IRsaKeySource privateKeySource, string data, string algorithm = "SHA512WITHRSA")
    {
        return Sign(new PrivateKeyProvider(privateKeySource.GetRsaKey().AsymmetricCipherKeyPair.Private), data,
            algorithm);
    }
}
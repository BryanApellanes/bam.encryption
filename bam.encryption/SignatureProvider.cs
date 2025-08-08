using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Bam.Encryption;

public class SignatureProvider : ISignatureProvider
{
    public ISignature Sign(IRsaKeySource privateKeySource, string data, string algorithm = "SHA512WITHRSA")
    {
        return Sign(new PrivateKeyProvider(privateKeySource.GetRsaKey().AsymmetricCipherKeyPair.Private), data,
            algorithm);
    }

    public ISignature Sign(IPrivateKeyProvider privateKeySource, string data, string algorithm = "SHA512WITHRSA")
    {
        ISigner signer = SignerUtilities.GetSigner(algorithm);
        signer.Init(true, privateKeySource.GetPrivateKey());
        
        byte[] dataBytes = Encoding.UTF8.GetBytes(data);
        signer.BlockUpdate(dataBytes, 0, dataBytes.Length);
        byte[] signature = signer.GenerateSignature();
        return new Signature()
        {
            SignatureBytes = signature,
            Data = data,
            Algorithm = algorithm,
        };
    }

    public ISignatureVerification VerifySignature(ISignature signature, IPublicKey issuerPublicKey)
    {
        try
        {
            ISigner signer = SignerUtilities.GetSigner(signature.Algorithm);
            signer.Init(false, issuerPublicKey.Value);
            byte[] dataToVerify = Encoding.UTF8.GetBytes(signature.Data);
            signer.BlockUpdate(dataToVerify, 0, signature.SignatureBytes.Length);
            return new SignatureVerification()
            {
                Signature = signature,
                Success = signer.VerifySignature(signature.SignatureBytes),
                Message = string.Empty,
                IssuerPublicKey = issuerPublicKey
            };
        }
        catch (Exception e)
        {
            return new SignatureVerification()
            {
                Signature = signature,
                Success = false,
                Message = e.Message,
                IssuerPublicKey = issuerPublicKey
            };
        }
    }
}
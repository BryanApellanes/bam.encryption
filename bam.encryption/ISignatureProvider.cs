using Bam.Encryption;

namespace Bam.Encryption;

public interface ISignatureProvider
{
    ISignature Sign(IRsaKeySource privateKeySource, string data, string algorithm = "SHA512WITHRSA");
    
    ISignature Sign(IPrivateKeyProvider privateKeySource, string data, string algorithm = "SHA512WITHRSA");
    ISignatureVerification VerifySignature(ISignature signature, IPublicKey issuerPublicKey);
}
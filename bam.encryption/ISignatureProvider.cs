using Bam.Encryption;

namespace Bam.Encryption;

public interface ISignatureProvider
{
    ISignature Sign(IPrivateKeyProvider privateKeySource, string data, string algorithm = "SHA512WITHRSA");
    ISignatureVerification VerifySignature(ISignature signature, IPublicKey issuerPublicKey);
}
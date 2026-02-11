namespace Bam.Encryption;

public class EccSignatureProvider : SignatureProvider, IEccSignatureProvider
{
    public ISignature Sign(IEccKeySource eccKeySource, string data, string algorithm = "SHA256WITHECDSA")
    {
        return Sign(new PrivateKeyProvider(eccKeySource.GetEccKey()), data, algorithm);
    }
}

namespace Bam.Encryption;

public interface IEccSignatureProvider : ISignatureProvider
{
    ISignature Sign(IEccKeySource eccKeySource, string data, string algorithm = "SHA256WITHECDSA");
}

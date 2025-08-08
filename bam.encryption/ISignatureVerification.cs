namespace Bam.Encryption;

public interface ISignatureVerification
{
    ISignature Signature { get; set; }
    bool Success { get; set; }
    string Message { get; set; }
    IPublicKey IssuerPublicKey { get; set; }
}
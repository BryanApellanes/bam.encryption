namespace Bam.Encryption;

public class SignatureVerification : ISignatureVerification
{
    public ISignature Signature { get; set; }
    public bool Success { get; set; }
    public string Message { get; set; }
    public IPublicKey IssuerPublicKey { get; set; }
}
namespace Bam.Encryption;

public class Signature : ISignature
{
    public byte[] SignatureBytes { get; set; }
    public string SignatureBase64 { get => SignatureBytes.ToBase64(); }
    public string Data { get; set; }
    public string Algorithm { get; set; }
}
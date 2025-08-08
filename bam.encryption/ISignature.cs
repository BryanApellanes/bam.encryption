namespace Bam.Encryption;

public interface ISignature
{
    byte[] SignatureBytes { get; }
    string SignatureBase64 { get; }
    string Data { get; }
    string Algorithm { get; }
}
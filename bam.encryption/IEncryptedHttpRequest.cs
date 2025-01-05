namespace Bam.Encryption
{
    public interface IEncryptedHttpRequest : IHttpRequest
    {
        Cipher ContentCipher { get; }
    }
}
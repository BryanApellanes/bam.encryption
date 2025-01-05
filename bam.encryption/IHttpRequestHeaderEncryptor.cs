namespace Bam.Encryption
{
    public interface IHttpRequestHeaderEncryptor
    {
        IEncryptor Encryptor { get; }

        void EncryptHeaders(IHttpRequest request);
    }
}
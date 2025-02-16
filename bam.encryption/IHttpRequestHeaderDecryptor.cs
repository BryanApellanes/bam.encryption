namespace Bam.Encryption
{
    public interface IHttpRequestHeaderDecryptor
    {
        IDecryptor Decryptor { get; }

        void DecryptHeaders(IHttpRequest request);
    }
}

namespace Bam.Encryption
{
    public interface IEncryptedHttpRequest<TContent> : IEncryptedHttpRequest, IHttpRequest<TContent>
    {
        new ContentCipher<TContent> ContentCipher { get; }
    }
}

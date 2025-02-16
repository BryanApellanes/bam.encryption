using Bam.Encryption;

namespace Bam.shared.Encryption
{
    public interface IHttpRequestDecryptor<TContent> : IHttpRequestDecryptor
    {
        new IContentDecryptor<TContent> ContentDecryptor { get; }

        IHttpRequest<TContent> DecryptRequest(IEncryptedHttpRequest<TContent> request);
    }
}

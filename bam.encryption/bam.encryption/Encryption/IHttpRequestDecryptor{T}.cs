using Bam.Net.Encryption;
using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.net.shared.Encryption
{
    public interface IHttpRequestDecryptor<TContent> : IHttpRequestDecryptor
    {
        new IContentDecryptor<TContent> ContentDecryptor { get; }

        IHttpRequest<TContent> DecryptRequest(IEncryptedHttpRequest<TContent> request);
    }
}

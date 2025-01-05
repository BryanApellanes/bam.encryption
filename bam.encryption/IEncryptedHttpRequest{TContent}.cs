using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public interface IEncryptedHttpRequest<TContent> : IEncryptedHttpRequest, IHttpRequest<TContent>
    {
        new ContentCipher<TContent> ContentCipher { get; }
    }
}

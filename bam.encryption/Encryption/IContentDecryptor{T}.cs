using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public interface IContentDecryptor<TContent> : IDecryptor<TContent>
    {
        TContent DecryptContentCipher(ContentCipher<TContent> contentCipher);
    }
}

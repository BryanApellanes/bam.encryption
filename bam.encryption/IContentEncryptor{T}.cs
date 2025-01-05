using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public interface IContentEncryptor<TContent> : IEncryptor<TContent>
    {
        ContentCipher<TContent> GetContentCipher(TContent content);
    }
}

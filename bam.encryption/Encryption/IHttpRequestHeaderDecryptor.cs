using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public interface IHttpRequestHeaderDecryptor
    {
        IDecryptor Decryptor { get; }

        void DecryptHeaders(IHttpRequest request);
    }
}

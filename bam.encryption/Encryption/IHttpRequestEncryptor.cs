﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public interface IHttpRequestEncryptor
    {
        IEncryptor ContentEncryptor { get;  }
        IHttpRequestHeaderEncryptor HeaderEncryptor { get; }

        EncryptedHttpRequest EncryptRequest(IHttpRequest request);
    }
}

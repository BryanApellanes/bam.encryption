using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public interface IContentCipher
    {
        byte[] Data { get; }
        string ContentType { get; }
    }
}

using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public class SymmetricContentCipher<TContent> : ContentCipher<TContent>
    {
        public SymmetricContentCipher(byte[] data)
        {
            this.Data = data;
            this.ContentType = MediaTypes.SymmetricCipher;
        }
    }
}

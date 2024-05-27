using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public class AsymmetricContentCipher : ContentCipher
    {
        public AsymmetricContentCipher(byte[] data)
        {
            this.Data = data;
            this.ContentType = MediaTypes.AsymmetricCipher;
        }
    }
}

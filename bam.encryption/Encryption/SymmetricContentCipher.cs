﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public class SymmetricContentCipher : ContentCipher
    {
        public SymmetricContentCipher(byte[] data)
        {
            this.Data = data;
            this.ContentType = MediaTypes.SymmetricCipher;
        }
    }
}

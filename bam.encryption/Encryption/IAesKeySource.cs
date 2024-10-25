﻿using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public interface IAesKeySource
    {
        /// <summary>
        /// Get an aes key.
        /// </summary>
        /// <returns>AesKeyVectorPair</returns>
        AesKeyVectorPair GetAesKey();
    }
}

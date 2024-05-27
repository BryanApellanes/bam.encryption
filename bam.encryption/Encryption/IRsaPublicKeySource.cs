using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public interface IRsaPublicKeySource
    {
        RsaPublicKey GetRsaPublicKey();
    }
}

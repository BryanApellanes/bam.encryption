using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public interface IRsaKeySource : IRsaPublicKeySource
    {
        RsaPublicPrivateKeyPair GetRsaKey();
    }
}

using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public interface IClientKeySource : IAesKeySource, IRsaPublicKeySource
    {
    }
}

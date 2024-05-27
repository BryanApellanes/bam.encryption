using Bam.Encryption;
using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.shared.Encryption
{
    public interface IServerKeySource : IAesKeySource, IRsaKeySource
    {
    }
}

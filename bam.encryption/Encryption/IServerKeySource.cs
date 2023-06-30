using Bam.Net.Encryption;
using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.net.shared.Encryption
{
    public interface IServerKeySource : IAesKeySource, IRsaKeySource
    {
    }
}

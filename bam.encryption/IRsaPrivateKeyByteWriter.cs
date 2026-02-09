using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    public interface IRsaPrivateKeyByteWriter
    {
        bool WritePrivateKeyBytes(RsaPublicPrivateKeyPair keyPair);
        bool WritePrivateKeyBytes(byte[] privateKeyBytes);
    }
}

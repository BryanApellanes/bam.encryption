using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    public interface IRsaPrivateKeyByteReader
    {
        RsaPublicPrivateKeyPair ReadPrivateKey(byte[] privateKeyBytes);
    }
}

using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    public class RsaPrivateKeyByteReader : IRsaPrivateKeyByteReader
    {
        public RsaPublicPrivateKeyPair ReadPrivateKey(byte[] privateKeyBytes)
        {
            return new RsaPublicPrivateKeyPair(privateKeyBytes);
        }
    }
}

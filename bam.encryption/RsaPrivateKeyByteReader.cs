using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    /// <summary>
    /// Reads RSA private key bytes and reconstructs the corresponding RSA key pair.
    /// </summary>
    public class RsaPrivateKeyByteReader : IRsaPrivateKeyByteReader
    {
        /// <inheritdoc />
        public RsaPublicPrivateKeyPair ReadPrivateKey(byte[] privateKeyBytes)
        {
            return new RsaPublicPrivateKeyPair(privateKeyBytes);
        }
    }
}

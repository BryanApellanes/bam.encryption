using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    /// <summary>
    /// Defines a reader that can reconstruct an RSA key pair from private key bytes.
    /// </summary>
    public interface IRsaPrivateKeyByteReader
    {
        /// <summary>
        /// Reads private key bytes and returns the corresponding RSA public-private key pair.
        /// </summary>
        /// <param name="privateKeyBytes">The raw private key bytes to read.</param>
        /// <returns>The RSA public-private key pair.</returns>
        RsaPublicPrivateKeyPair ReadPrivateKey(byte[] privateKeyBytes);
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    /// <summary>
    /// Defines a writer that persists RSA private key bytes to storage.
    /// </summary>
    public interface IRsaPrivateKeyByteWriter
    {
        /// <summary>
        /// Writes the private key bytes from the specified RSA key pair.
        /// </summary>
        /// <param name="keyPair">The RSA key pair whose private key bytes to write.</param>
        /// <returns>True if the write succeeded; otherwise, false.</returns>
        bool WritePrivateKeyBytes(RsaPublicPrivateKeyPair keyPair);

        /// <summary>
        /// Writes the specified raw private key bytes.
        /// </summary>
        /// <param name="privateKeyBytes">The raw private key bytes to write.</param>
        /// <returns>True if the write succeeded; otherwise, false.</returns>
        bool WritePrivateKeyBytes(byte[] privateKeyBytes);
    }
}

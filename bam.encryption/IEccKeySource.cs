using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    /// <summary>
    /// Defines a source that provides both public and private ECC key pairs.
    /// </summary>
    public interface IEccKeySource : IEccPublicKeySource
    {
        /// <summary>
        /// Gets the ECC public-private key pair.
        /// </summary>
        /// <returns>The ECC public-private key pair.</returns>
        EccPublicPrivateKeyPair GetEccKey();
    }
}

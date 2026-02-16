using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    /// <summary>
    /// Defines a source that provides an ECC public key.
    /// </summary>
    public interface IEccPublicKeySource
    {
        /// <summary>
        /// Gets the ECC public key.
        /// </summary>
        /// <returns>The ECC public key.</returns>
        EccPublicKey GetEccPublicKey();
    }
}

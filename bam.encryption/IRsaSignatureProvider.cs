using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    /// <summary>
    /// Defines a provider that creates digital signatures using RSA keys.
    /// </summary>
    public interface IRsaSignatureProvider : ISignatureProvider
    {
        /// <summary>
        /// Signs the specified data using the RSA key from the given source.
        /// </summary>
        /// <param name="privateKeySource">The source of the RSA key pair used for signing.</param>
        /// <param name="data">The data to sign.</param>
        /// <param name="algorithm">The signing algorithm to use; defaults to SHA512WITHRSA.</param>
        /// <returns>The digital signature.</returns>
        ISignature Sign(IRsaKeySource privateKeySource, string data, string algorithm = "SHA512WITHRSA");
    }
}

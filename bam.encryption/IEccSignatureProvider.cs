using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    public interface IEccSignatureProvider : ISignatureProvider
    {
                ISignature Sign(IRsaKeySource privateKeySource, string data, string algorithm = "SHA512WITHRSA");

    }
}

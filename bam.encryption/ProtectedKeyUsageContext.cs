using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    public abstract class ProtectedKeyUsageContext : IDisposable
    {
        public abstract void Dispose();

        public abstract void UseKey(Action<IPrivateKey> action);
    }
}

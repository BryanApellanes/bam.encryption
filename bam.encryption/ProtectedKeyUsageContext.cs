using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    /// <summary>
    /// Abstract base class that provides a disposable context for safely using private keys in memory.
    /// </summary>
    public abstract class ProtectedKeyUsageContext : IDisposable
    {
        /// <inheritdoc />
        public abstract void Dispose();

        /// <summary>
        /// Executes the specified action with temporary access to the private key.
        /// </summary>
        /// <param name="action">The action to execute with the private key.</param>
        public abstract void UseKey(Action<IPrivateKey> action);
    }
}

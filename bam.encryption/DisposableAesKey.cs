using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    /// <summary>
    /// Abstract base class for AES keys that securely clears key material from memory on disposal.
    /// </summary>
    public abstract class DisposableAesKey : IDisposable
    {
        private bool _disposed = false;

        /// <summary>
        /// Gets or sets the raw AES key bytes.
        /// </summary>
        public virtual byte[] Key { get; set; }

        /// <summary>
        /// Gets or sets the raw initialization vector bytes.
        /// </summary>
        public virtual byte[] IV { get; set; }

        /// <summary>
        /// Securely clears the key and IV from memory and releases resources.
        /// </summary>
        public void Dispose()
        {
            // Dispose of unmanaged resources.
            Dispose(true);
            // Suppress finalization.
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                Array.Clear(Key, 0, Key.Length);
                Array.Clear(IV, 0, IV.Length);
            }

            _disposed = true;
        }
    }
}

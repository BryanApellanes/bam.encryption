using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    /// <summary>
    /// Abstract base class that holds PEM-encoded key data and securely clears it from memory on disposal.
    /// </summary>
    public abstract class DisposablePem : IDisposable
    {
        private bool _disposed = false;

        /// <summary>
        /// Gets or sets the PEM-encoded key data as a byte array.
        /// </summary>
        public byte[] Pem { get; set; } = null!;

        /// <summary>
        /// Clears the PEM data from memory and releases resources.
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

            if (disposing && Pem != null)
            {
                Array.Clear(Pem, 0, Pem.Length);
            }

            _disposed = true;
        }
    }
}

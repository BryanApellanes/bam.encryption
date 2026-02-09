using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    public abstract class DisposablePem : IDisposable
    {
        private bool _disposed = false;

        public byte[] Pem { get; set; }

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

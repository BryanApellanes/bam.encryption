using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    public abstract class DisposableAesKey : IDisposable
    {
        private bool _disposed = false;

        internal byte[] Key { get; set; }
        internal byte[] IV { get; set; }

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

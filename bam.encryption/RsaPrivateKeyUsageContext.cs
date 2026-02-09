using Microsoft.CodeAnalysis.VisualBasic.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bam.Encryption
{
    public class RsaPrivateKeyUsageContext : ProtectedKeyUsageContext
    {
        byte[] _privateKeyCipher;
        bool _disposed = false;
        AesKey _aesKey;
        public RsaPrivateKeyUsageContext(byte[] privateKeyBytes)
        {
            this._aesKey = new AesKey();
            this._privateKeyCipher = this._aesKey.EncryptBytes(privateKeyBytes);
        }

        public override void Dispose()
        {
            // Dispose of unmanaged resources.
            Dispose(true);
            // Suppress finalization.
            GC.SuppressFinalize(this);
        }

        public override void UseKey(Action<IPrivateKey> action)
        {
            byte[] privateKeyBytes = this._aesKey.DecryptBytes(this._privateKeyCipher);
            using(RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair(privateKeyBytes))
            {
                action(new RsaPrivateKey(keyPair));
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                Array.Clear(_privateKeyCipher, 0, _privateKeyCipher.Length);
            }

            _disposed = true;
        }
    }
}

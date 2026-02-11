using System;

namespace Bam.Encryption
{
    /// <summary>
    /// Protects an AES key in memory by encrypting it with an ephemeral AES key.
    /// The original key material is zeroed after construction. Key material is only
    /// available within a UseKey callback and is zeroed immediately after.
    /// Follows the same pattern as RsaPrivateKeyUsageContext.
    /// </summary>
    public class ProtectedAesKeyUsageContext : IDisposable
    {
        byte[] _keyCipher;
        byte[] _ivCipher;
        bool _disposed = false;
        AesKey _ephemeralKey;

        public ProtectedAesKeyUsageContext(AesKey key)
        {
            _ephemeralKey = new AesKey();
            _keyCipher = _ephemeralKey.EncryptBytes(key.Key);
            _ivCipher = _ephemeralKey.EncryptBytes(key.IV);
            Array.Clear(key.Key, 0, key.Key.Length);
            Array.Clear(key.IV, 0, key.IV.Length);
        }

        public void UseKey(Action<AesKey> action)
        {
            byte[] keyBytes = _ephemeralKey.DecryptBytes(_keyCipher);
            byte[] ivBytes = _ephemeralKey.DecryptBytes(_ivCipher);
            using (AesKey tempKey = new AesKey(keyBytes, ivBytes))
            {
                action(tempKey);
            }
        }

        public T UseKey<T>(Func<AesKey, T> func)
        {
            byte[] keyBytes = _ephemeralKey.DecryptBytes(_keyCipher);
            byte[] ivBytes = _ephemeralKey.DecryptBytes(_ivCipher);
            using (AesKey tempKey = new AesKey(keyBytes, ivBytes))
            {
                return func(tempKey);
            }
        }

        public void Dispose()
        {
            Dispose(true);
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
                if (_keyCipher != null)
                {
                    Array.Clear(_keyCipher, 0, _keyCipher.Length);
                }

                if (_ivCipher != null)
                {
                    Array.Clear(_ivCipher, 0, _ivCipher.Length);
                }

                _ephemeralKey?.Dispose();
            }

            _disposed = true;
        }
    }
}

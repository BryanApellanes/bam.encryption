/*
	Copyright © Bryan Apellanes 2015  
*/

using System.Text;

namespace Bam.Encryption
{
    /// <summary>
    /// Represents a portable key and initialization vector for use in Aes encryption and decryption operations.
    /// </summary>
    [Serializable]
    public class AesKey : IAesKeySource
    {
        public const string SystemKeyFileName = "aes.sys";

        static AesKey()
        {
            SetSystemKey();
        }
        
        public AesKey()
        {
            SetKeyAndIv();
        }

        public AesKey(string base64EncodedKey, string base64EncodedIv)
        {
            this.Key = base64EncodedKey;
            this.Iv = base64EncodedIv;
        }

        public AesKey(byte[] key, byte[] iv)
        {
            this.Key = key.ToBase64();
            this.Iv = iv.ToBase64();
        }

        private void SetKeyAndIv()
        {
            System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
            aes.GenerateKey();
            aes.GenerateIV();
            this.Key = Convert.ToBase64String(aes.Key);
            this.Iv = Convert.ToBase64String(aes.IV);
        }

        protected static string SystemKeyFilePath
        {
            get => Path.Combine(BamProfile.VaultsDotSys, SystemKeyFileName);
        }
        
        private static AesKey _systemKey;
        private static object _systemKeyLock = new object();
        public static AesKey SystemKey
        {
            get
            {
                if (_systemKey == null)
                {
                    lock (_systemKeyLock)
                    {
                        SetSystemKey();
                    }
                }
                
                return _systemKey;
            }
        }

        private static AesKey SetSystemKey()
        {
            string filePath = SystemKeyFilePath;
            if (File.Exists(filePath))
            {
                _systemKey = File.ReadAllText(filePath).FromJson<AesKey>();
            }
            else
            {
                _systemKey = new AesKey();
                _systemKey.ToJsonFile(filePath);
            }

            return _systemKey;
        }

        public static AesKey Next()
        {
            if (_systemKey == null)
            {
                return SystemKey;
            }
            string backupToPath = SystemKeyFilePath.GetNextFileName();
            File.Move(SystemKeyFilePath, backupToPath);
            return SetSystemKey();
        }
        
        /// <summary>
        /// Gets or sets the base 64 encoded key.
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        public string Key { get; set; }

        /// <summary>
        /// Gets or sets the base 64 encoded initialization vector.
        /// </summary>
        /// <value>
        /// The iv.
        /// </value>
        public string Iv { get; set; }

        /// <summary>
        /// Gets a Base64 encoded value representing the cipher of the specified
        /// value using the current key.
        /// </summary>
        public string Encrypt(string plainText)
        {
            return Aes.Encrypt(plainText, this);
        }

        /// <summary>
        /// Decrypts the specified base64 encoded value.
        /// </summary>
        /// <param name="base64EncodedCipher">The base64 encoded value.</param>
        /// <returns></returns>
        public string Decrypt(string base64EncodedCipher)
        {
            return Aes.Decrypt(base64EncodedCipher, this);
        }

        public byte[] EncryptBytes(byte[] data)
        {
            return Aes.EncryptBytes(data, this.Key, this.Iv);
        }

        public byte[] DecryptBytes(byte[] cipherData)
        {
            return Aes.DecryptBytes(cipherData, this.Key, this.Iv);
        }

        public AesKey GetAesKey()
        {
            return this;
        }
    }
}

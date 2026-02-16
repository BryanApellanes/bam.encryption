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
    public class AesKey : DisposableAesKey, IAesKeySource
    {
        /// <summary>
        /// The file name used for the system-wide AES key.
        /// </summary>
        public const string SystemKeyFileName = "aes.sys";

        static AesKey()
        {
            SetSystemKey();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesKey"/> class, generating a random key and IV.
        /// </summary>
        public AesKey()
        {
            SetKeyAndIv();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesKey"/> class from Base64-encoded key and IV strings.
        /// </summary>
        /// <param name="base64EncodedKey">The Base64-encoded AES key.</param>
        /// <param name="base64EncodedIV">The Base64-encoded initialization vector.</param>
        public AesKey(string base64EncodedKey, string base64EncodedIV)
        {
            this.Key = base64EncodedKey.FromBase64();
            this.IV = base64EncodedIV.FromBase64();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesKey"/> class from raw key and IV byte arrays.
        /// </summary>
        /// <param name="key">The raw AES key bytes.</param>
        /// <param name="iv">The raw initialization vector bytes.</param>
        public AesKey(byte[] key, byte[] iv)
        {
            this.Key = key;
            this.IV = iv;
        }

        private void SetKeyAndIv()
        {
            System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
            aes.GenerateKey();
            aes.GenerateIV();
            this.Key = aes.Key;
            this.IV = aes.IV;
        }

        protected static string SystemKeyFilePath
        {
            get => Path.Combine(BamProfile.VaultsDotSys, SystemKeyFileName);
        }
        
        private static AesKey _systemKey;
        private static object _systemKeyLock = new object();
        /// <summary>
        /// Gets the system-wide AES key, loading or creating it from disk as needed.
        /// </summary>
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

        /// <summary>
        /// Rotates the system key by backing up the current key file and generating a new one.
        /// </summary>
        /// <returns>The new system AES key.</returns>
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
        public override byte[] Key { get; set; }

        /// <summary>
        /// Gets or sets the base 64 encoded initialization vector.
        /// </summary>
        /// <value>
        /// The iv.
        /// </value>
        public override byte[] IV { get; set; }

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

        /// <summary>
        /// Encrypts the specified byte array using this key.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <returns>The encrypted byte array.</returns>
        public byte[] EncryptBytes(byte[] data)
        {
            return Aes.EncryptBytes(data, this.Key, this.IV);
        }

        /// <summary>
        /// Decrypts the specified cipher byte array using this key.
        /// </summary>
        /// <param name="cipherData">The encrypted byte array to decrypt.</param>
        /// <returns>The decrypted byte array.</returns>
        public byte[] DecryptBytes(byte[] cipherData)
        {
            return Aes.DecryptBytes(cipherData, this.Key, this.IV);
        }

        /// <summary>
        /// Returns this instance as the AES key.
        /// </summary>
        /// <returns>This <see cref="AesKey"/> instance.</returns>
        public AesKey GetAesKey()
        {
            return this;
        }
    }
}

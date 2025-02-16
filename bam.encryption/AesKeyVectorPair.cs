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
    public class AesKeyVectorPair : IAesKeySource
    {
        public const string SystemKeyFileName = "bamkey.aes";

        public AesKeyVectorPair()
        {
            SetKeyAndIv();
        }

        public AesKeyVectorPair(string base64EncodedKey, string base64EncodedIv)
        {
            this.Key = base64EncodedKey;
            this.Iv = base64EncodedIv;
        }

        static readonly object _aesLock = new object();
        static volatile AesKeyVectorPair _key;

        /// <summary>
        /// Gets the advanced encryption key vector pair for the currently running bam system.
        /// </summary>
        public static AesKeyVectorPair SystemKey
        {
            get
            {
                if (_key == null)
                {
                    lock(_aesLock)
                    {
                        string fileName = Path.Combine(BamHome.Local, SystemKeyFileName);
                        if (File.Exists(fileName))
                        {
                            _key = LoadXmlBase64(fileName);
                        }
                        else
                        {
                            _key = new AesKeyVectorPair();
                            _key.SaveXmlBase64(fileName);
                        }
                    }
                }

                return _key;
            }
        }

        private void SetKeyAndIv()
        {
            System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
            aes.GenerateKey();
            aes.GenerateIV();
            this.Key = Convert.ToBase64String(aes.Key);
            this.Iv = Convert.ToBase64String(aes.IV);
        }

        public void SaveJson(string filePath)
        {
            this.ToJsonFile(new FileInfo(filePath));
        }

        public static AesKeyVectorPair LoadJson(string filePath)
        {
            return filePath.FromJsonFile<AesKeyVectorPair>();
        }
        
        public void SaveXmlBase64(string filePath)
        {
            FileInfo fileInfo = new FileInfo(filePath);
            if (fileInfo.Directory != null && !fileInfo.Directory.Exists)
            {
                fileInfo.Directory.Create();
            }
            string xml = this.ToXml();
            byte[] xmlBytes = Encoding.UTF8.GetBytes(xml);
            string xmlBase64 = Convert.ToBase64String(xmlBytes);
            using StreamWriter sw = new StreamWriter(filePath);
            sw.Write(xmlBase64);
        }

        public static AesKeyVectorPair LoadXmlBase64(string filePath)
        {
            using (StreamReader sr = new StreamReader(filePath))
            {
                string xmlBase64 = sr.ReadToEnd();
                byte[] xmlBytes = Convert.FromBase64String(xmlBase64);
                string xml = Encoding.UTF8.GetString(xmlBytes);
                return xml.FromXml<AesKeyVectorPair>();
            }
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
        /// Gets a Base64 encoded value representing the cypher of the specified
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

        public AesKeyVectorPair GetAesKey()
        {
            return this;
        }
    }
}

/*
	Copyright © Bryan Apellanes 2015  
*/

using System.Text;
using System.Security.Cryptography;

namespace Bam.Encryption
{ 
    public static class Aes
    {
        /// <summary>
        /// Gets a Base64 encoded value representing the cypher of the specified value
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string Encrypt(string value)
        {
            return Encrypt(value, XmlBase64Aeskey.SystemKey);
        }

        public static string Encrypt(string value, string password)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] aesKey = SHA256.Create().ComputeHash(passwordBytes);
            byte[] aesIV = MD5.Create().ComputeHash(passwordBytes);

            return Encrypt(value, aesKey.ToBase64(), aesIV.ToBase64());
        }

        public static string Decrypt(string value, string password)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] aesKey = SHA256.Create().ComputeHash(passwordBytes);
            byte[] aesIV = MD5.Create().ComputeHash(passwordBytes);

            return Decrypt(value, aesKey, aesIV);   
        }
        
        /// <summary>
        /// Gets a Base64 encoded value representing the cypher of the specified
        /// value using the specified key.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static string Encrypt(string value, AesKey key)
        {
            return Encrypt(value, key.Key, key.IV);
        }

        public static string Encrypt(string plainText, byte[] key, byte[] iv)
        {
            System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
            aes.IV = iv;
            aes.Key = key;
            aes.Padding = PaddingMode.PKCS7;
                
            ICryptoTransform encryptor = aes.CreateEncryptor();
            byte[] encryptedBytes = Encrypt(plainText, encryptor);
            return Convert.ToBase64String(encryptedBytes);
        }

        /// <summary>
        /// Encrypts the specified value.
        /// </summary>
        /// <param name="plainText">The value.</param>
        /// <param name="base64EncodedKey">The base64 encoded key.</param>
        /// <param name="base64EncodedIV">The base64 encoded iv.</param>
        /// <returns>Base64 encoded encrypted value</returns>
        public static string Encrypt(string plainText, string base64EncodedKey, string base64EncodedIV)
        {
            System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
            aes.IV = Convert.FromBase64String(base64EncodedIV);
            aes.Key = Convert.FromBase64String(base64EncodedKey);
            aes.Padding = PaddingMode.PKCS7;
                
            ICryptoTransform encryptor = aes.CreateEncryptor();

            byte[] encryptedBytes = Encrypt(plainText, encryptor);
            return Convert.ToBase64String(encryptedBytes);
        }

        public static byte[] Encrypt(string plainText, ICryptoTransform encryptor)
        {
            using (MemoryStream encryptBuffer = new MemoryStream())
            {
                using (CryptoStream encryptStream = new CryptoStream(encryptBuffer, encryptor, CryptoStreamMode.Write))
                {
                    byte[] data = Encoding.UTF8.GetBytes(plainText);
                    encryptStream.Write(data, 0, data.Length);
                    encryptStream.FlushFinalBlock();
                    return encryptBuffer.ToArray();
                }
            }
        }

        public static byte[] EncryptBytes(byte[] plainData, byte[] key, byte[] iv)
        {
            System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
            aes.IV = iv;
            aes.Key = key;
            aes.Padding = PaddingMode.PKCS7;
            
            ICryptoTransform encryptor = aes.CreateEncryptor();
            return EncryptBytes(plainData, encryptor);
        }

        public static byte[] EncryptBytes(byte[] plainData, string base64EncodedKey, string base64EncodedIV)
        {
            System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
            aes.IV = Convert.FromBase64String(base64EncodedIV);
            aes.Key = Convert.FromBase64String(base64EncodedKey);
            aes.Padding = PaddingMode.PKCS7;
            
            ICryptoTransform encryptor = aes.CreateEncryptor();

            return EncryptBytes(plainData, encryptor);            
        }

        public static byte[] EncryptBytes(byte[] plainData, ICryptoTransform encryptor)
        {
            using (MemoryStream encryptBuffer = new MemoryStream())
            {
                using (CryptoStream encryptStream = new CryptoStream(encryptBuffer, encryptor, CryptoStreamMode.Write))
                {
                    encryptStream.Write(plainData, 0, plainData.Length);
                    encryptStream.FlushFinalBlock();
                    return encryptBuffer.ToArray();
                }
            }
        }

        /// <summary>
        /// Decrypts the specified base64 encoded value.
        /// </summary>
        /// <param name="base64EncodedValue">The base64 encoded value.</param>
        /// <returns></returns>
        public static string Decrypt(string base64EncodedValue)
        {
            return Decrypt(base64EncodedValue, XmlBase64Aeskey.SystemKey);
        }

        /// <summary>
        /// Decrypts the specified base64 encoded value.
        /// </summary>
        /// <param name="base64EncodedCipher">The base64 encoded cipher.</param>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        public static string Decrypt(string base64EncodedCipher, AesKey key)
        {
            return Decrypt(base64EncodedCipher, key.Key, key.IV);
        }

        public static string Decrypt(string base64EncodedCipher, byte[] key, byte[] iv, Encoding? encoding = null)
        {
            byte[] encData = Convert.FromBase64String(base64EncodedCipher);
            byte[] retBytes = DecryptBytes(encData, key, iv);
            return (encoding ?? Encoding.UTF8).GetString(retBytes);
        }

        public static string Decrypt(byte[] cipher, byte[] key, byte[] iv, Encoding? encoding = null)
        {
            byte[] retBytes = DecryptBytes(cipher, key, iv);
            return (encoding ?? Encoding.UTF8).GetString(retBytes);
        }

        public static byte[] DecryptBytes(byte[] cipher, byte[] key, byte[] iv)
        {
            System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
            aes.IV = iv;
            aes.Key = key;
            aes.Padding = PaddingMode.PKCS7;
            
            byte[] plainText = null;
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(cipher, 0, cipher.Length);
                }
                plainText = ms.ToArray();
            }
            return plainText;
        }

        /// <summary>
        /// Encrypts the specified target after converting to xml writing it to the specified 
        /// file path.
        /// </summary>
        /// <param name="target">The target.</param>
        /// <param name="filePath">The file path.</param>
        /// <returns></returns>
        public static AesKey Encrypt(this object target, string filePath)
        {
            return Encrypt(target, filePath, filePath + ".key", true);
        }

        /// <summary>
        /// Encrypts the specified target using the specified key file after converting to xml, then writes it to the specified 
        /// file path.
        /// </summary>
        /// <param name="target">The target.</param>
        /// <param name="filePath">The file path.</param>
        /// <param name="keyFilePath">The key file path.</param>
        /// <returns></returns>
        public static AesKey Encrypt(this object target, string filePath, string keyFilePath)
        {
            return Encrypt(target, filePath, keyFilePath, true);
        }

        public static AesKey Encrypt(this object target, string filePath, string keyFilePath, bool writeKeyFile)
        {
            string text = ToBase64EncodedEncryptedXml(target, out XmlBase64Aeskey key);
            using (StreamWriter sw = new StreamWriter(filePath))
            {
                sw.Write(text);
            }

            if (writeKeyFile)
            {
                key.SaveXmlBase64(keyFilePath);
            }
            return key;
        }

        public static T Decrypt<T>(string filePath)
        {
            FileInfo info = new FileInfo(filePath);
            string keyFile = info.FullName + ".key";
            return Decrypt<T>(filePath, keyFile);
        }

        public static T Decrypt<T>(string filePath, string keyFile)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException(string.Format("The file specified to deserialize from {0} does not exist", filePath));
            }

            if (!File.Exists(keyFile))
            {
                throw new FileNotFoundException(string.Format("The key file specified {0} does not exist", keyFile));
            }

            AesKey key = XmlBase64Aeskey.LoadXmlBase64(keyFile); 

            return Decrypt<T>(filePath, key);
        }

        public static T Decrypt<T>(string filePath, AesKey key)
        {
            string text;
            using (StreamReader sr = new StreamReader(filePath))
            {
                text = sr.ReadToEnd();                
            }
            return Deserialize<T>(text, key);
        }
        
        /// <summary>
        /// Get a base64 encoded encrypted xml serialization string representing the specified target object
        /// </summary>
        /// <param name="target">The object to serialize</param>
        /// <param name="key">The key used to encrypt and decrypt the resulting string</param>
        /// <returns>string</returns>
        public static string ToBase64EncodedEncryptedXml(this object target, out XmlBase64Aeskey key)
        {
            string xml = ObjectExtensions.ToXml(target);
            AesManaged rm = new AesManaged();
            rm.GenerateIV();
            rm.GenerateKey();
            key = new XmlBase64Aeskey()
            {
                Key = rm.Key,
                IV = rm.IV
            };
            byte[] encryptedBytes = Encrypt(xml, rm.CreateEncryptor());
            return Convert.ToBase64String(encryptedBytes);
        }

        /// <summary>
        /// Deserializes the specified base64 encrypted XML string.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="base64EncryptedXmlString">The base64 encrypted XML string.</param>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        public static T Deserialize<T>(string base64EncryptedXmlString, AesKey key)
        {
            string xml = Decrypt(base64EncryptedXmlString, key.Key, key.IV);
            return Bam.StringExtensions.FromXml<T>(xml);
        }
    }
}

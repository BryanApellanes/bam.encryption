/*
	Copyright © Bryan Apellanes 2015  
*/

using System.Text;
using System.Security.Cryptography;

namespace Bam.Encryption
{
    /// <summary>
    /// Provides static methods for AES encryption and decryption of strings, byte arrays, and objects.
    /// </summary>
    public static class Aes
    {
        /// <summary>
        /// Encrypts the specified value using the system AES key.
        /// </summary>
        /// <param name="value">The plain text value to encrypt.</param>
        /// <returns>A Base64-encoded string representing the encrypted value.</returns>
        public static string Encrypt(string value)
        {
            return Encrypt(value, XmlBase64Aeskey.SystemKey);
        }

        /// <summary>
        /// Encrypts the specified value using a key and IV derived from the given password.
        /// </summary>
        /// <param name="value">The plain text value to encrypt.</param>
        /// <param name="password">The password used to derive the AES key (SHA256) and IV (MD5).</param>
        /// <returns>A Base64-encoded string representing the encrypted value.</returns>
        public static string Encrypt(string value, string password)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] aesKey = SHA256.Create().ComputeHash(passwordBytes);
            byte[] aesIV = MD5.Create().ComputeHash(passwordBytes);

            return Encrypt(value, aesKey.ToBase64(), aesIV.ToBase64());
        }

        /// <summary>
        /// Decrypts the specified value using a key and IV derived from the given password.
        /// </summary>
        /// <param name="value">The Base64-encoded cipher text to decrypt.</param>
        /// <param name="password">The password used to derive the AES key (SHA256) and IV (MD5).</param>
        /// <returns>The decrypted plain text string.</returns>
        public static string Decrypt(string value, string password)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] aesKey = SHA256.Create().ComputeHash(passwordBytes);
            byte[] aesIV = MD5.Create().ComputeHash(passwordBytes);

            return Decrypt(value, aesKey, aesIV);   
        }
        
        /// <summary>
        /// Encrypts the specified value using the provided AES key.
        /// </summary>
        /// <param name="value">The plain text value to encrypt.</param>
        /// <param name="key">The AES key containing the key and IV to use for encryption.</param>
        /// <returns>A Base64-encoded string representing the encrypted value.</returns>
        public static string Encrypt(string value, AesKey key)
        {
            return Encrypt(value, key.Key, key.IV);
        }

        /// <summary>
        /// Encrypts the specified plain text using the provided raw AES key and IV bytes.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="key">The raw AES key bytes.</param>
        /// <param name="iv">The raw initialization vector bytes.</param>
        /// <returns>A Base64-encoded string representing the encrypted value.</returns>
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
        /// Encrypts the specified plain text using Base64-encoded AES key and IV.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="base64EncodedKey">The Base64-encoded AES key.</param>
        /// <param name="base64EncodedIV">The Base64-encoded initialization vector.</param>
        /// <returns>A Base64-encoded string representing the encrypted value.</returns>
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

        /// <summary>
        /// Encrypts the specified plain text using the provided crypto transform.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="encryptor">The cryptographic transform used for encryption.</param>
        /// <returns>The encrypted byte array.</returns>
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

        /// <summary>
        /// Encrypts the specified byte array using the provided raw AES key and IV bytes.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="key">The raw AES key bytes.</param>
        /// <param name="iv">The raw initialization vector bytes.</param>
        /// <returns>The encrypted byte array.</returns>
        public static byte[] EncryptBytes(byte[] plainData, byte[] key, byte[] iv)
        {
            System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
            aes.IV = iv;
            aes.Key = key;
            aes.Padding = PaddingMode.PKCS7;
            
            ICryptoTransform encryptor = aes.CreateEncryptor();
            return EncryptBytes(plainData, encryptor);
        }

        /// <summary>
        /// Encrypts the specified byte array using Base64-encoded AES key and IV.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="base64EncodedKey">The Base64-encoded AES key.</param>
        /// <param name="base64EncodedIV">The Base64-encoded initialization vector.</param>
        /// <returns>The encrypted byte array.</returns>
        public static byte[] EncryptBytes(byte[] plainData, string base64EncodedKey, string base64EncodedIV)
        {
            System.Security.Cryptography.Aes aes = System.Security.Cryptography.Aes.Create();
            aes.IV = Convert.FromBase64String(base64EncodedIV);
            aes.Key = Convert.FromBase64String(base64EncodedKey);
            aes.Padding = PaddingMode.PKCS7;
            
            ICryptoTransform encryptor = aes.CreateEncryptor();

            return EncryptBytes(plainData, encryptor);            
        }

        /// <summary>
        /// Encrypts the specified byte array using the provided crypto transform.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="encryptor">The cryptographic transform used for encryption.</param>
        /// <returns>The encrypted byte array.</returns>
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
        /// Decrypts the specified Base64-encoded cipher using the system AES key.
        /// </summary>
        /// <param name="base64EncodedValue">The Base64-encoded cipher text to decrypt.</param>
        /// <returns>The decrypted plain text string.</returns>
        public static string Decrypt(string base64EncodedValue)
        {
            return Decrypt(base64EncodedValue, XmlBase64Aeskey.SystemKey);
        }

        /// <summary>
        /// Decrypts the specified Base64-encoded cipher using the provided AES key.
        /// </summary>
        /// <param name="base64EncodedCipher">The Base64-encoded cipher text to decrypt.</param>
        /// <param name="key">The AES key containing the key and IV to use for decryption.</param>
        /// <returns>The decrypted plain text string.</returns>
        public static string Decrypt(string base64EncodedCipher, AesKey key)
        {
            return Decrypt(base64EncodedCipher, key.Key, key.IV);
        }

        /// <summary>
        /// Decrypts the specified Base64-encoded cipher using the provided raw AES key and IV bytes.
        /// </summary>
        /// <param name="base64EncodedCipher">The Base64-encoded cipher text to decrypt.</param>
        /// <param name="key">The raw AES key bytes.</param>
        /// <param name="iv">The raw initialization vector bytes.</param>
        /// <param name="encoding">The text encoding to use for the decrypted result. Defaults to UTF-8.</param>
        /// <returns>The decrypted plain text string.</returns>
        public static string Decrypt(string base64EncodedCipher, byte[] key, byte[] iv, Encoding? encoding = null)
        {
            byte[] encData = Convert.FromBase64String(base64EncodedCipher);
            byte[] retBytes = DecryptBytes(encData, key, iv);
            return (encoding ?? Encoding.UTF8).GetString(retBytes);
        }

        /// <summary>
        /// Decrypts the specified cipher byte array using the provided raw AES key and IV bytes.
        /// </summary>
        /// <param name="cipher">The encrypted byte array to decrypt.</param>
        /// <param name="key">The raw AES key bytes.</param>
        /// <param name="iv">The raw initialization vector bytes.</param>
        /// <param name="encoding">The text encoding to use for the decrypted result. Defaults to UTF-8.</param>
        /// <returns>The decrypted plain text string.</returns>
        public static string Decrypt(byte[] cipher, byte[] key, byte[] iv, Encoding? encoding = null)
        {
            byte[] retBytes = DecryptBytes(cipher, key, iv);
            return (encoding ?? Encoding.UTF8).GetString(retBytes);
        }

        /// <summary>
        /// Decrypts the specified cipher byte array using the provided raw AES key and IV bytes.
        /// </summary>
        /// <param name="cipher">The encrypted byte array to decrypt.</param>
        /// <param name="key">The raw AES key bytes.</param>
        /// <param name="iv">The raw initialization vector bytes.</param>
        /// <returns>The decrypted byte array.</returns>
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
        /// Encrypts the specified object as XML and writes it to the specified file path, saving the AES key to a .key file alongside it.
        /// </summary>
        /// <param name="target">The object to serialize and encrypt.</param>
        /// <param name="filePath">The file path to write the encrypted data to.</param>
        /// <returns>The AES key used for encryption.</returns>
        public static AesKey Encrypt(this object target, string filePath)
        {
            return Encrypt(target, filePath, filePath + ".key", true);
        }

        /// <summary>
        /// Encrypts the specified object as XML and writes it to the specified file path, saving the AES key to the specified key file path.
        /// </summary>
        /// <param name="target">The object to serialize and encrypt.</param>
        /// <param name="filePath">The file path to write the encrypted data to.</param>
        /// <param name="keyFilePath">The file path to save the AES key to.</param>
        /// <returns>The AES key used for encryption.</returns>
        public static AesKey Encrypt(this object target, string filePath, string keyFilePath)
        {
            return Encrypt(target, filePath, keyFilePath, true);
        }

        /// <summary>
        /// Encrypts the specified object as XML and writes it to the specified file path, optionally saving the AES key to a file.
        /// </summary>
        /// <param name="target">The object to serialize and encrypt.</param>
        /// <param name="filePath">The file path to write the encrypted data to.</param>
        /// <param name="keyFilePath">The file path to save the AES key to.</param>
        /// <param name="writeKeyFile">If true, writes the AES key to the key file path.</param>
        /// <returns>The AES key used for encryption.</returns>
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

        /// <summary>
        /// Decrypts and deserializes an object from the specified file, loading the AES key from a .key file alongside it.
        /// </summary>
        /// <typeparam name="T">The type to deserialize the decrypted XML into.</typeparam>
        /// <param name="filePath">The file path containing the encrypted data.</param>
        /// <returns>The deserialized object.</returns>
        public static T Decrypt<T>(string filePath)
        {
            FileInfo info = new FileInfo(filePath);
            string keyFile = info.FullName + ".key";
            return Decrypt<T>(filePath, keyFile);
        }

        /// <summary>
        /// Decrypts and deserializes an object from the specified file using the AES key loaded from the specified key file.
        /// </summary>
        /// <typeparam name="T">The type to deserialize the decrypted XML into.</typeparam>
        /// <param name="filePath">The file path containing the encrypted data.</param>
        /// <param name="keyFile">The file path containing the AES key.</param>
        /// <returns>The deserialized object.</returns>
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

        /// <summary>
        /// Decrypts and deserializes an object from the specified file using the provided AES key.
        /// </summary>
        /// <typeparam name="T">The type to deserialize the decrypted XML into.</typeparam>
        /// <param name="filePath">The file path containing the encrypted data.</param>
        /// <param name="key">The AES key to use for decryption.</param>
        /// <returns>The deserialized object.</returns>
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

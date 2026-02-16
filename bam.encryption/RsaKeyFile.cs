/*
	Copyright © Bryan Apellanes 2015  
*/

using System.Text;
using System.Security.Cryptography;
using Bam.Configuration;

namespace Bam.Encryption
{
    /// <summary>
    /// Manages RSA key pairs stored as XML files on disk, providing encryption and decryption using .NET RSACryptoServiceProvider.
    /// </summary>
    public class RsaKeyFile
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaKeyFile"/> class, generating a new RSA key pair.
        /// </summary>
        public RsaKeyFile()
        {
            RSACryptoServiceProvider initial = CreateRSACryptoServiceProvider(Rsa.DefaultKeySize);
            PublicKeyXml = initial.ToXmlString(false);
            PrivateKeyXml = initial.ToXmlString(true);
        }
        
        static object _defaultLock = new object();
        static RsaKeyFile _rsaKeyPair;
        /// <summary>
        /// Gets the default RSA key file, loading from disk or creating a new one if needed.
        /// </summary>
        public static RsaKeyFile Default
        {
            get
            {
                return _defaultLock.DoubleCheckLock(ref _rsaKeyPair, () =>
                {
                    string applicationName = DefaultConfiguration.GetAppSetting("ApplicationName", DefaultConfiguration.DefaultApplicationName);
                    RsaKeyFile result = new RsaKeyFile();
                    if (result.PubExists(applicationName, out string pubKeyPath) &&
                        result.PrivExists(applicationName, out string privKeyPath))
                    {
                        LoadPublic(result, pubKeyPath);
                        LoadPrivate(result, privKeyPath);
                    }
                    else
                    {
                        result.Save(applicationName);
                    }

                    return result;
                });
            }
        }

        protected bool PubExists(string fileName, out string filePath)
        {
            return Exists(fileName, "pub", out filePath);
        }

        protected bool PrivExists(string fileName, out string filePath)
        {
            return Exists(fileName, "priv", out filePath);
        }

        private bool Exists(string fileName, string ext, out string filePath)
        {
            filePath = Path.Combine(RuntimeSettings.ProcessDataFolder, $"{fileName}.{ext}");
            return File.Exists(filePath);
        }

        /// <summary>
        /// Gets or sets the XML-encoded public key.
        /// </summary>
        public string PublicKeyXml { get; set; }

        /// <summary>
        /// Gets or sets the XML-encoded private key.
        /// </summary>
        public string PrivateKeyXml { get; set; }

        /// <summary>
        /// Saves the key pair files to the process data folder with the specified file name.
        /// </summary>
        /// <param name="fileName">The base file name (without extension) for the key files.</param>
        public void Save(string fileName)
        {
            Save(RuntimeSettings.ProcessDataFolder, fileName);
        }

        /// <summary>
        /// Saves the key pair as .pub and .priv files in the specified directory.
        /// </summary>
        /// <param name="directory">The directory to save the key files to.</param>
        /// <param name="fileName">The base file name (without extension) for the key files.</param>
        public void Save(string directory, string fileName)
        {
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            string pubFile = Path.Combine(directory, string.Format("{0}.pub", fileName));
            using (StreamWriter sw = new StreamWriter(pubFile))
            {
                sw.Write(PublicKeyXml);
            }

            string privFile = Path.Combine(directory, string.Format("{0}.priv", fileName));
            using (StreamWriter sw = new StreamWriter(privFile))
            {
                sw.Write(PrivateKeyXml);
            }
        }

        /// <summary>
        /// Loads an RSA key file from the current directory with the specified file name.
        /// </summary>
        /// <param name="fileName">The base file name (without extension) of the key files.</param>
        /// <returns>The loaded RSA key file.</returns>
        public static RsaKeyFile Load(string fileName)
        {
            return Load(".", fileName);
        }

        /// <summary>
        /// Loads an RSA key file from the specified directory with the specified file name.
        /// </summary>
        /// <param name="directory">The directory containing the key files.</param>
        /// <param name="fileName">The base file name (without extension) of the key files.</param>
        /// <returns>The loaded RSA key file.</returns>
        public static RsaKeyFile Load(string directory, string fileName)
        {
            RsaKeyFile result = new RsaKeyFile();
            string pubFile = Path.Combine(directory, string.Format("{0}.pub", fileName));
            LoadPublic(result, pubFile);
            string privFile = Path.Combine(directory, string.Format("{0}.priv", fileName));
            LoadPrivate(result, privFile);
            return result;
        }

        protected static void LoadPublic(RsaKeyFile keys, string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new InvalidOperationException("The specified filePath was not found");
            }

            keys.PublicKeyXml = File.ReadAllText(filePath);
        }

        protected static void LoadPrivate(RsaKeyFile keys, string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new InvalidOperationException("The specified filePath was not found");
            }

            keys.PrivateKeyXml = File.ReadAllText(filePath);
        }

        /// <summary>
        /// Gets an RSACryptoServiceProvider initialized with the public key.
        /// </summary>
        public RSACryptoServiceProvider PublicKey
        {
            get
            {
                RSACryptoServiceProvider publicKey = CreateRSACryptoServiceProvider(Rsa.DefaultKeySize);
                publicKey.FromXmlString(PublicKeyXml);
                return publicKey;
            }
        }


        /// <summary>
        /// Gets an RSACryptoServiceProvider initialized with the private key.
        /// </summary>
        public RSACryptoServiceProvider PrivateKey
        {
            get
            {
                RSACryptoServiceProvider privateKey = CreateRSACryptoServiceProvider(Rsa.DefaultKeySize);
                privateKey.FromXmlString(PrivateKeyXml);
                return privateKey;
            }
        }

        /// <summary>
        /// Encrypts the specified value using the public key.
        /// </summary>
        /// <param name="value">The plain text to encrypt.</param>
        /// <returns>The Base64-encoded cipher text.</returns>
        public string EncryptWithPublicKey(string value)
        {
            return Encrypt(value, PublicKey, Encoding.UTF8);
        }

        /// <summary>
        /// Decrypts the specified Base64-encoded cipher text using the private key.
        /// </summary>
        /// <param name="base64EncodedCipher">The Base64-encoded cipher text to decrypt.</param>
        /// <returns>The decrypted plain text.</returns>
        public string DecryptWithPrivateKey(string base64EncodedCipher)
        {
            return Decrypt(base64EncodedCipher, PrivateKey, Encoding.UTF8);
        }

        private string Decrypt(string base64EncodedCipher, RSACryptoServiceProvider key, Encoding encoding)
        {
            byte[] enc = Convert.FromBase64String(base64EncodedCipher);
            byte[] denc = key.Decrypt(enc, false);
            return encoding.GetString(denc);
        }

        private string Encrypt(string value, RSACryptoServiceProvider key, Encoding encoding)
        {
            byte[] data = encoding.GetBytes(value);
            byte[] enc = key.Encrypt(data, false);
            string base64Enc = Convert.ToBase64String(enc);
            return base64Enc;
        }

        private static RSACryptoServiceProvider CreateRSACryptoServiceProvider(int keySize = 1024)
        {
            CspParameters RSAParams = new CspParameters
            {
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            RSACryptoServiceProvider publicKey = new RSACryptoServiceProvider(keySize, RSAParams);
            return publicKey;
        }
    }
}

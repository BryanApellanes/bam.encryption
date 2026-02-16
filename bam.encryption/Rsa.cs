/*
	Copyright © Bryan Apellanes 2015  
*/
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;

namespace Bam.Encryption
{
    /// <summary>
    /// Provides static RSA encryption and decryption methods and key pair generation utilities.
    /// </summary>
    public static class Rsa
    {
        static Rsa()
        {
            DefaultKeySize = 1024;
        }

        /// <summary>
        /// Gets or sets the default RSA key size in bits.
        /// </summary>
        public static int DefaultKeySize { get; set; }

        /// <summary>
        /// Encrypts the specified value using the default RSA key file's public key.
        /// </summary>
        /// <param name="value">The plain text to encrypt.</param>
        /// <returns>The encrypted Base64-encoded cipher text.</returns>
        public static string Encrypt(string value)
        {
            return RsaKeyFile.Default.EncryptWithPublicKey(value);
        }

        /// <summary>
        /// Decrypts the specified cipher text using the default RSA key file's private key.
        /// </summary>
        /// <param name="cipherText">The Base64-encoded cipher text to decrypt.</param>
        /// <returns>The decrypted plain text.</returns>
        public static string Decrypt(string cipherText)
        {
            return RsaKeyFile.Default.DecryptWithPrivateKey(cipherText);
        }

        /// <summary>
        /// Gets the default RSA public key as an XML string.
        /// </summary>
        /// <returns>The XML-encoded public key.</returns>
        public static string GetPublicKey()
        {
            return RsaKeyFile.Default.PublicKeyXml;
        }

        /// <summary>
        /// Generates a new RSA key pair with the specified key length.
        /// </summary>
        /// <param name="size">The RSA key length to use.</param>
        /// <returns>The generated asymmetric cipher key pair.</returns>
        public static AsymmetricCipherKeyPair GenerateKeyPair(RsaKeyLength size)
        {
            return size.RsaKeyPair();
        }

        /// <summary>
        /// Gets an RSA cipher engine, optionally wrapped with PKCS1 padding.
        /// </summary>
        /// <param name="usePkcsPadding">True to use PKCS1 padding; false for no padding.</param>
        /// <returns>The asymmetric block cipher engine.</returns>
        public static IAsymmetricBlockCipher GetRsaEngine(bool usePkcsPadding)
        {
            IAsymmetricBlockCipher result = new RsaEngine();
            if (usePkcsPadding)
            {
                result = new Pkcs1Encoding(result); // wrap the engine in a padded encoding
            }

            return result;
        }
    }
}

/*
	Copyright © Bryan Apellanes 2015  
*/
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System.Text;

namespace Bam.Encryption
{
    /// <summary>
    /// Provides extension methods for RSA and AES encryption and decryption operations on strings and byte arrays.
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Encrypts the specified plain text using AES with a password-derived key via Rijndael.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="password">The password used to derive the encryption key.</param>
        /// <returns>The encrypted cipher text as a Base64 string.</returns>
        public static string AesPasswordEncrypt(this string plainText, string password)
        {
            return new PasswordEncrypted(plainText, password);            
        }

        /// <summary>
        /// Decrypts the specified AES-encrypted cipher text using a password-derived key via Rijndael.
        /// </summary>
        /// <param name="cipher">The Base64-encoded cipher text to decrypt.</param>
        /// <param name="password">The password used to derive the decryption key.</param>
        /// <returns>The decrypted plain text.</returns>
        public static string AesPasswordDecrypt(this string cipher, string password)
        {
            return new PasswordDecrypted(cipher, password);            
        }
        
        public static AsymmetricCipherKeyPair RsaKeyPair(this RsaKeyLength size, string secureRandomAlgorithm = "SHA1PRNG")
        {
            return RsaKeyPair((int)size, secureRandomAlgorithm);
        }

        /// <summary>
        /// Generates an RSA key pair of the specified bit size.
        /// </summary>
        /// <param name="size">The key size in bits (e.g., 1024, 2048, 4096).</param>
        /// <param name="secureRandomAlgorithm">The secure random algorithm to use. Defaults to "SHA1PRNG".</param>
        /// <returns>A new RSA asymmetric cipher key pair.</returns>
        public static AsymmetricCipherKeyPair RsaKeyPair(this int size, string secureRandomAlgorithm = "SHA1PRNG")
        {
            RsaKeyPairGenerator gen = new RsaKeyPairGenerator();
            RsaKeyGenerationParameters parameters = new RsaKeyGenerationParameters(new BigInteger("10001", 16), SecureRandom.GetInstance(secureRandomAlgorithm), size, 80);
            gen.Init(parameters);
            return gen.GenerateKeyPair();
        }

        /*public static void EcKeyPair()
        {
            ECKeyPairGenerator gen = new ECKeyPairGenerator();
            ECKeyGenerationParameters parameters = new ECKeyGenerationParameters()
        }*/
        
        /// <summary>
        /// Gets a base 64 encoded asymmetric cipher of the specified input.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="publicPemKey"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string EncryptWithPublicKey(this string input, string publicPemKey, Encoding encoding = null)
        {
            return EncryptWithPublicKey(input, publicPemKey.PemToKey(), encoding);
        }
        
        /// <summary>
        /// Gets a base 64 encoded asymmetric cipher of the specified plain text input.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="key"></param>
        /// <param name="encoding"></param>
        /// <param name="engine"></param>
        /// <returns></returns>
        public static string EncryptWithPublicKey(this string plainText, AsymmetricKeyParameter key, Encoding encoding = null, IAsymmetricBlockCipher engine = null)
        {
            byte[] encrypted = GetPublicKeyEncryptedBytes(plainText, key, encoding, engine);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts the specified plain text with the given public key and returns the encrypted bytes.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="key">The asymmetric public key to encrypt with.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8.</param>
        /// <param name="engine">The asymmetric block cipher engine to use. Defaults to RSA.</param>
        /// <returns>The encrypted byte array.</returns>
        public static byte[] GetPublicKeyEncryptedBytes(this string plainText, AsymmetricKeyParameter key, Encoding encoding = null, IAsymmetricBlockCipher engine = null)
        {
            if (encoding == null)
            {
                encoding = Encoding.UTF8;
            }

            byte[] plainData = encoding.GetBytes(plainText);
            byte[] encrypted = plainData.AsymmetricEncrypt(key, engine);
            return encrypted;
        }

        /// <summary>
        /// Encrypts the specified byte array using the public key from a PEM string.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="publicPemKey">The PEM-encoded public key.</param>
        /// <param name="engine">The asymmetric block cipher engine to use. Defaults to RSA.</param>
        /// <returns>The encrypted byte array.</returns>
        public static byte[] GetPublicKeyEncryptedBytes(this byte[] plainData, string publicPemKey, IAsymmetricBlockCipher engine = null)
        {
            return GetPublicKeyEncryptedBytes(plainData, publicPemKey.PemToKey(), engine);
        }

        /// <summary>
        /// Encrypts the specified byte array using the given asymmetric public key.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="key">The asymmetric public key to encrypt with.</param>
        /// <param name="engine">The asymmetric block cipher engine to use. Defaults to RSA.</param>
        /// <returns>The encrypted byte array.</returns>
        public static byte[] GetPublicKeyEncryptedBytes(this byte[] plainData, AsymmetricKeyParameter key, IAsymmetricBlockCipher engine = null)
        {
            byte[] encrypted = plainData.AsymmetricEncrypt(key, engine);
            return encrypted;
        }

        /// <summary>
        /// Decrypts the specified Base64-encoded cipher using the private key from a key pair.
        /// </summary>
        /// <param name="base64EncodedCipher">The Base64-encoded cipher text to decrypt.</param>
        /// <param name="keys">The asymmetric key pair containing the private key.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8.</param>
        /// <returns>The decrypted plain text string.</returns>
        public static string DecryptWithPrivateKey(this string base64EncodedCipher, AsymmetricCipherKeyPair keys, Encoding encoding = null)
        {
            return DecryptWithPrivateKey(base64EncodedCipher, keys.Private, encoding, false);
        }

        /// <summary>
        /// Decrypts the specified Base64-encoded cipher using the given private key.
        /// </summary>
        /// <param name="base64EncodedCipher">The Base64-encoded cipher text to decrypt.</param>
        /// <param name="privateKey">The asymmetric private key to decrypt with.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8.</param>
        /// <param name="usePkcsPadding">If true, uses PKCS#1 padding on the RSA engine.</param>
        /// <returns>The decrypted plain text string.</returns>
        public static string DecryptWithPrivateKey(this string base64EncodedCipher, AsymmetricKeyParameter privateKey, Encoding encoding = null, bool usePkcsPadding = false)
        {
            return DecryptWithPrivateKey(base64EncodedCipher, privateKey, encoding, Rsa.GetRsaEngine(usePkcsPadding));
        }

        /// <summary>
        /// Decrypts the specified Base64-encoded cipher using the given private key and cipher engine.
        /// </summary>
        /// <param name="base64EncodedCipher">The Base64-encoded cipher text to decrypt.</param>
        /// <param name="privateKey">The asymmetric private key to decrypt with.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8.</param>
        /// <param name="engine">The asymmetric block cipher engine to use. Defaults to RSA.</param>
        /// <returns>The decrypted plain text string.</returns>
        public static string DecryptWithPrivateKey(this string base64EncodedCipher, AsymmetricKeyParameter privateKey, Encoding encoding = null, IAsymmetricBlockCipher engine = null)
        {
            byte[] decrypted = GetPrivateKeyDecryptedBytes(base64EncodedCipher, privateKey, engine);
            if (encoding == null)
            {
                encoding = Encoding.UTF8;
            }
            return encoding.GetString(decrypted);
        }

        /// <summary>
        /// Decrypts a Base64-encoded cipher and returns the raw decrypted bytes.
        /// </summary>
        /// <param name="base64EncodedCipher">The Base64-encoded cipher text to decrypt.</param>
        /// <param name="privateKey">The asymmetric private key to decrypt with.</param>
        /// <param name="engine">The asymmetric block cipher engine to use.</param>
        /// <returns>The decrypted byte array.</returns>
        public static byte[] GetPrivateKeyDecryptedBytes(this string base64EncodedCipher, AsymmetricKeyParameter privateKey, IAsymmetricBlockCipher engine)
        {
            byte[] encrypted = Convert.FromBase64String(base64EncodedCipher);
            byte[] decrypted = DecryptWithPrivateKey(encrypted, privateKey, engine);
            return decrypted;
        }

        /// <summary>
        /// Decrypts the specified Base64-encoded cipher using the private key from a PEM string.
        /// </summary>
        /// <param name="base64EncodedCipher">The Base64-encoded cipher text to decrypt.</param>
        /// <param name="pemString">The PEM-encoded private key string.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8.</param>
        /// <returns>The decrypted plain text string.</returns>
        public static string DecryptWithPrivateKey(this string base64EncodedCipher, string pemString, Encoding encoding = null)
        {
            if (encoding == null)
            {
                encoding = Encoding.UTF8;
            }

            return DecryptWithPrivateKey(base64EncodedCipher, pemString.PemToKeyPair(), encoding);
        }

        /// <summary>
        /// Encrypt with the Public key of the specified keyPair
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="keyPair"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string EncryptWithPublicKey(this string plainText, AsymmetricCipherKeyPair keyPair, Encoding encoding = null)
        {
            if (encoding == null)
            {
                encoding = Encoding.UTF8;
            }

            byte[] data = encoding.GetBytes(plainText);
            byte[] encrypted = data.EncryptWithPublicKey(keyPair);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts the specified byte array using the public key from a key pair.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="keyPair">The key pair containing the public key.</param>
        /// <returns>The encrypted byte array.</returns>
        public static byte[] EncryptWithPublicKey(this byte[] plainData, AsymmetricCipherKeyPair keyPair)
        {
            return AsymmetricEncrypt(plainData, keyPair.Public);
        }

        /// <summary>
        /// Encrypts the specified byte array using asymmetric encryption with the given key.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="key">The asymmetric key to encrypt with.</param>
        /// <param name="usePkcsPadding">If true, uses PKCS#1 padding on the RSA engine.</param>
        /// <returns>The encrypted byte array.</returns>
        public static byte[] AsymmetricEncrypt(this byte[] plainData, AsymmetricKeyParameter key, bool usePkcsPadding = false)
        {
            return AsymmetricEncrypt(plainData, key, Rsa.GetRsaEngine(usePkcsPadding));
        }

        /// <summary>
        /// Encrypts the specified byte array using asymmetric encryption with the given key and cipher engine, processing data in blocks.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="key">The asymmetric key to encrypt with.</param>
        /// <param name="e">The asymmetric block cipher engine to use. Defaults to RSA if null.</param>
        /// <returns>The encrypted byte array.</returns>
        public static byte[] AsymmetricEncrypt(this byte[] plainData, AsymmetricKeyParameter key, IAsymmetricBlockCipher e)
        {
            if (e == null)
            {
                e = new RsaEngine();
            }

            e.Init(true, key);

            int blockSize = e.GetInputBlockSize();
            List<byte> output = new List<byte>();
            for (int chunkPosition = 0; chunkPosition < plainData.Length; chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, plainData.Length - (chunkPosition * blockSize));
                output.AddRange(e.ProcessBlock(plainData, chunkPosition, chunkSize));
            }

            return output.ToArray();
        }

        /// <summary>
        /// Decrypts the specified encrypted byte array using the given private key and cipher engine, processing data in blocks.
        /// </summary>
        /// <param name="byteArrayCipher">The encrypted byte array to decrypt.</param>
        /// <param name="key">The asymmetric private key to decrypt with.</param>
        /// <param name="engine">The asymmetric block cipher engine to use. Defaults to RSA if null.</param>
        /// <returns>The decrypted byte array.</returns>
        public static byte[] DecryptWithPrivateKey(this byte[] byteArrayCipher, AsymmetricKeyParameter key, IAsymmetricBlockCipher? engine = null)
        {
            if (engine == null)
            {
                engine = new RsaEngine();
            }

            engine.Init(false, key);

            int blockSize = engine.GetInputBlockSize();

            List<byte> output = new List<byte>();
            for (int chunkPosition = 0; chunkPosition < byteArrayCipher.Length; chunkPosition += blockSize)
            {
                int chunkSize = Math.Min(blockSize, byteArrayCipher.Length - (chunkPosition * blockSize));
                output.AddRange(engine.ProcessBlock(byteArrayCipher, chunkPosition, chunkSize));
            }

            return output.ToArray();
        }
    }
}

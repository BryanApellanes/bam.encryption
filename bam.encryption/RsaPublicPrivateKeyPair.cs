using Org.BouncyCastle.Crypto;
using System.Text;

namespace Bam.Encryption
{
    /// <summary>
    /// Represents an RSA public-private key pair that supports encryption, decryption, and PEM serialization.
    /// </summary>
    public class RsaPublicPrivateKeyPair : DisposablePem, IRsaKeySource
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaPublicPrivateKeyPair"/> class, generating a new RSA key pair with the specified key length.
        /// </summary>
        /// <param name="rsaKeyLength">The RSA key length to use; defaults to 4096 bits.</param>
        /// <param name="encoding">The encoding to use for PEM conversion; defaults to UTF-8 if null.</param>
        public RsaPublicPrivateKeyPair(RsaKeyLength rsaKeyLength = RsaKeyLength._4096, Encoding? encoding = null)
        {
            this.RsaKeyLength = rsaKeyLength;
            this.AsymmetricCipherKeyPair = Rsa.GenerateKeyPair(rsaKeyLength);
            this.Pem = AsymmetricCipherKeyPair.ToPem(encoding);
            this.PublicKeyPem = AsymmetricCipherKeyPair.PublicKeyToPem();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaPublicPrivateKeyPair"/> class from PEM-encoded private key bytes.
        /// </summary>
        /// <param name="pemBytes">The PEM-encoded private key bytes.</param>
        /// <param name="encoding">The encoding to use for PEM conversion; defaults to UTF-8 if null.</param>
        public RsaPublicPrivateKeyPair(byte[] pemBytes, Encoding? encoding = null)
        {
            this.RsaKeyLength = RsaKeyLength.Unkown;
            this.Pem = pemBytes;
            this.AsymmetricCipherKeyPair = pemBytes.PemToKeyPair(encoding);
            this.PublicKeyPem = AsymmetricCipherKeyPair.PublicKeyToPem();
        }

        AsymmetricCipherKeyPair? _asymmetricCipherKeyPair;
        protected internal AsymmetricCipherKeyPair AsymmetricCipherKeyPair
        {
            get => _asymmetricCipherKeyPair ??= Pem.PemToKeyPair();
            set => _asymmetricCipherKeyPair = value;
        }

        /// <summary>
        /// Gets or sets the RSA key length used to generate this key pair.
        /// </summary>
        public RsaKeyLength RsaKeyLength { get; set; }

        /// <summary>
        /// Gets the public key as a pem string.
        /// </summary>
        public string PublicKeyPem { get; private set; }

        /// <summary>
        /// Gets a base 64 encoded cipher for the specified plain text.
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public string Encrypt(string plainText, Encoding? encoding = null)
        {
            byte[] plainData = (encoding ?? Encoding.UTF8).GetBytes(plainText);
            byte[] encrypted = Encrypt(plainData);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Deciphers the specified base 64 encoded cipher text.
        /// </summary>
        /// <param name="base64Cipher"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public string Decrypt(string base64Cipher, Encoding? encoding = null)
        {
            byte[] cipherBytes = base64Cipher.FromBase64();
            byte[] decrypted = Decrypt(cipherBytes);
            return (encoding ?? Encoding.UTF8).GetString(decrypted);
        }

        /// <summary>
        /// Using the public key gets an encrypted byte array for the specified plain data.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="usePkcsPadding">A value indicating whether to use padding, the default is false.</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] plainData, bool usePkcsPadding)
        {
            return Encrypt(plainData, Rsa.GetRsaEngine(usePkcsPadding));
        }

        /// <summary>
        /// Using the public key gets an encrypted byte array for the specified plain data.
        /// </summary>
        /// <param name="plainData"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] plainData, IAsymmetricBlockCipher? engine = null)
        {
            return plainData.GetPublicKeyEncryptedBytes(_asymmetricCipherKeyPair!.Public, engine);
        }
        
        /// <summary>
        /// Using the private key, gets an unencrypted byte array for the specified cipher.
        /// </summary>
        /// <param name="cipherBytes">The data to decrypt.</param>
        /// <param name="usePkcsPadding">A value indicating whether the cipher is pkcs padded.</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] cipherBytes, bool usePkcsPadding)
        {
            return Decrypt(cipherBytes, Rsa.GetRsaEngine(usePkcsPadding));
        }

        /// <summary>
        /// Using the private key, gets an unencrypted byte array for the specified cipher.
        /// </summary>
        /// <param name="cipherBytes"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] cipherBytes, IAsymmetricBlockCipher? engine = null)
        {
            return cipherBytes.DecryptWithPrivateKey(AsymmetricCipherKeyPair.Private, engine);
        }

        /// <summary>
        /// Gets the underlying BouncyCastle asymmetric cipher key pair.
        /// </summary>
        /// <returns>The asymmetric cipher key pair.</returns>
        public AsymmetricCipherKeyPair GetAsymmetricCipherKeyPair()
        {
            return AsymmetricCipherKeyPair;
        }
        
        /// <summary>
        /// Gets the RSA public key from this key pair.
        /// </summary>
        /// <returns>A new <see cref="RsaPublicKey"/> instance containing the public key.</returns>
        public RsaPublicKey GetRsaPublicKey()
        {
            return new RsaPublicKey(PublicKeyPem);
        }

        /// <summary>
        /// Returns this instance as the RSA key pair.
        /// </summary>
        /// <returns>This <see cref="RsaPublicPrivateKeyPair"/> instance.</returns>
        public RsaPublicPrivateKeyPair GetRsaKey()
        {
            return this;
        }
    }
}

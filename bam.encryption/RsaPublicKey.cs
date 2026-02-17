using Org.BouncyCastle.Crypto;
using System.Text;

namespace Bam.Encryption
{
    /// <summary>
    /// Represents an RSA public key that supports encryption operations.
    /// </summary>
    public class RsaPublicKey : PublicKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaPublicKey"/> class from a PEM-encoded public key string.
        /// </summary>
        /// <param name="publicKeyPem">The PEM-encoded RSA public key string.</param>
        public RsaPublicKey(string publicKeyPem) : base(publicKeyPem.PemToKey())
        {
            this.Pem = publicKeyPem;
        }

        /// <summary>
        /// Gets or sets the public key pem string.
        /// </summary>
        public new string Pem { get; set; }

        /// <summary>
        /// Encrypts the specified plain text string using this RSA public key and returns a Base64-encoded cipher.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="encoding">The character encoding to use; defaults to UTF-8 if null.</param>
        /// <returns>The Base64-encoded cipher text.</returns>
        public string Encrypt(string plainText, Encoding? encoding = null)
        {
            byte[] plainData = (encoding ?? Encoding.UTF8).GetBytes(plainText);
            byte[] encrypted = EncryptBytes(plainData);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Encrypts the specified byte array using this RSA public key with the specified padding option.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="usePkcsPadding">True to use PKCS padding; false otherwise.</param>
        /// <returns>The encrypted byte array.</returns>
        public byte[] EncryptBytes(byte[] plainData, bool usePkcsPadding)
        {
            return EncryptBytes(plainData, Rsa.GetRsaEngine(usePkcsPadding));
        }

        /// <summary>
        /// Encrypts the specified byte array using this RSA public key with an optional custom cipher engine.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <param name="engine">The asymmetric block cipher engine to use; defaults to the standard RSA engine if null.</param>
        /// <returns>The encrypted byte array.</returns>
        public byte[] EncryptBytes(byte[] plainData, IAsymmetricBlockCipher? engine = null)
        {
            return plainData.GetPublicKeyEncryptedBytes(this.Pem, engine);
        }
    }
}

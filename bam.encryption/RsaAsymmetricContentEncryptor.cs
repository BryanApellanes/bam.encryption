namespace Bam.Encryption
{
    /// <summary>
    /// Encrypts content using RSA asymmetric encryption and produces content ciphers.
    /// </summary>
    /// <typeparam name="TContent">The type of content to encrypt.</typeparam>
    public class RsaAsymmetricContentEncryptor<TContent> : RsaAsymmetricDataEncryptor<TContent>, IContentEncryptor<TContent>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAsymmetricContentEncryptor{TContent}"/> class with the specified RSA public key source.
        /// </summary>
        /// <param name="rsaPublicKeySource">The source of the RSA public key for encryption.</param>
        public RsaAsymmetricContentEncryptor(IRsaPublicKeySource rsaPublicKeySource) : base(rsaPublicKeySource)
        {
        }

        /// <summary>
        /// Encrypts the specified content and returns it as a typed content cipher.
        /// </summary>
        /// <param name="content">The content to encrypt.</param>
        /// <returns>A content cipher containing the encrypted data.</returns>
        public ContentCipher<TContent> GetContentCipher(TContent content)
        {
            return new AsymmetricContentCipher<TContent>(Encrypt(content));
        }
    }
}

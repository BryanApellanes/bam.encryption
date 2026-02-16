namespace Bam.Encryption
{
    /// <summary>
    /// A specialized data encryptor that produces content ciphers.
    /// </summary>
    /// <typeparam name="TContent"></typeparam>
    public class SymmetricContentEncryptor<TContent> : SymmetricDataEncryptor<TContent>, IContentEncryptor<TContent>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricContentEncryptor{TContent}"/> class with the specified AES key source.
        /// </summary>
        /// <param name="aesKeySource">The source of the AES key for encryption.</param>
        public SymmetricContentEncryptor(IAesKeySource aesKeySource) : base(aesKeySource)
        {
        }

        /// <summary>
        /// Encrypts the specified content and returns it as a typed content cipher.
        /// </summary>
        /// <param name="content">The content to encrypt.</param>
        /// <returns>A content cipher containing the encrypted data.</returns>
        public ContentCipher<TContent> GetContentCipher(TContent content)
        {
            return new SymmetricContentCipher<TContent>(Encrypt(content));
        }
    }
}

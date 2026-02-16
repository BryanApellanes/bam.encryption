namespace Bam.Encryption
{
    /// <summary>
    /// Decrypts typed content that was encrypted using AES symmetric encryption.
    /// </summary>
    /// <typeparam name="TContent">The type of content to decrypt.</typeparam>
    public class SymmetricContentDecryptor<TContent> : SymmetricDataDecryptor<TContent>, IContentDecryptor<TContent>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricContentDecryptor{TContent}"/> class with the specified AES key source.
        /// </summary>
        /// <param name="aesKeysource">The source of the AES key for decryption.</param>
        public SymmetricContentDecryptor(IAesKeySource aesKeysource) : base(new SymmetricDataEncryptor<TContent>(aesKeysource))
        {
        }

        /// <inheritdoc />
        public TContent DecryptContentCipher(ContentCipher<TContent> contentCipher)
        {
            return DecryptCipher((Cipher<TContent>)contentCipher);
        }
    }
}

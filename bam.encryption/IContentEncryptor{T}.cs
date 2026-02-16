namespace Bam.Encryption
{
    /// <summary>
    /// Defines a content-aware encryptor that produces content ciphers with associated content type metadata.
    /// </summary>
    /// <typeparam name="TContent">The type of content to encrypt.</typeparam>
    public interface IContentEncryptor<TContent> : IEncryptor<TContent>
    {
        /// <summary>
        /// Encrypts the specified content and returns it as a content cipher with content type metadata.
        /// </summary>
        /// <param name="content">The content to encrypt.</param>
        /// <returns>A content cipher containing the encrypted data and content type.</returns>
        ContentCipher<TContent> GetContentCipher(TContent content);
    }
}

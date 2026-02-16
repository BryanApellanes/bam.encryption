namespace Bam.Encryption
{
    /// <summary>
    /// Defines a content-aware decryptor that can decrypt content ciphers back to their original typed form.
    /// </summary>
    /// <typeparam name="TContent">The type of content to decrypt.</typeparam>
    public interface IContentDecryptor<TContent> : IDecryptor<TContent>
    {
        /// <summary>
        /// Decrypts the specified content cipher back to the original content.
        /// </summary>
        /// <param name="contentCipher">The content cipher to decrypt.</param>
        /// <returns>The decrypted content.</returns>
        TContent DecryptContentCipher(ContentCipher<TContent> contentCipher);
    }
}

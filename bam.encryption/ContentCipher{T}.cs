namespace Bam.Encryption
{
    /// <summary>
    /// Abstract base class for a typed cipher that includes content type metadata alongside the encrypted data.
    /// </summary>
    /// <typeparam name="TContent">The type of content that was encrypted.</typeparam>
    public abstract class ContentCipher<TContent> : Cipher<TContent>, IContentCipher
    {
        /// <summary>
        /// Implicitly converts a <see cref="ContentCipher{TContent}"/> to its raw byte array.
        /// </summary>
        /// <param name="cipher">The cipher to convert.</param>
        public static implicit operator byte[](ContentCipher<TContent> cipher)
        {
            return cipher.Data;
        }

        /// <summary>
        /// Implicitly converts a <see cref="ContentCipher{TContent}"/> to a Base64-encoded string.
        /// </summary>
        /// <param name="cipher">The cipher to convert.</param>
        public static implicit operator string(ContentCipher<TContent> cipher)
        {
            return cipher.Data.ToBase64();
        }

        /// <summary>
        /// Gets the media type describing the encryption scheme used (e.g., symmetric or asymmetric cipher).
        /// </summary>
        public string ContentType { get; protected set; } = null!;
    }
}

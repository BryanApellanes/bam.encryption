namespace Bam.Encryption
{
    /// <summary>
    /// Abstract base class for a cipher that includes content type metadata alongside the encrypted data.
    /// </summary>
    public abstract class ContentCipher : Cipher, IContentCipher
    {
        /// <summary>
        /// Implicitly converts a <see cref="ContentCipher"/> to its raw byte array.
        /// </summary>
        /// <param name="cipher">The cipher to convert.</param>
        public static implicit operator byte[](ContentCipher cipher)
        {
            return cipher.Data;
        }

        /// <summary>
        /// Implicitly converts a <see cref="ContentCipher"/> to a Base64-encoded string.
        /// </summary>
        /// <param name="cipher">The cipher to convert.</param>
        public static implicit operator string(ContentCipher cipher)
        {
            return cipher.Data.ToBase64();
        }
                

        /// <summary>
        /// Gets the media type describing the encryption scheme used (e.g., symmetric or asymmetric cipher).
        /// </summary>
        public string ContentType { get; protected set; }
    }
}

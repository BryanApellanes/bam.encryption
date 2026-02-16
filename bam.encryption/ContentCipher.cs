namespace Bam.Encryption
{
    /// <summary>
    /// Abstract base class for a cipher that includes content type metadata alongside the encrypted data.
    /// </summary>
    public abstract class ContentCipher : Cipher, IContentCipher
    {
        public static implicit operator byte[](ContentCipher cipher)
        {
            return cipher.Data;
        }

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

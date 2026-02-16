namespace Bam.Encryption
{
    /// <summary>
    /// Represents a typed symmetric (AES) content cipher containing encrypted data with the symmetric cipher content type.
    /// </summary>
    /// <typeparam name="TContent">The type of the original content that was encrypted.</typeparam>
    public class SymmetricContentCipher<TContent> : ContentCipher<TContent>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricContentCipher{TContent}"/> class with the specified encrypted data.
        /// </summary>
        /// <param name="data">The encrypted byte array.</param>
        public SymmetricContentCipher(byte[] data)
        {
            this.Data = data;
            this.ContentType = MediaTypes.SymmetricCipher;
        }
    }
}

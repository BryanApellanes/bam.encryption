namespace Bam.Encryption
{
    /// <summary>
    /// Represents a symmetric (AES) content cipher containing encrypted data with the symmetric cipher content type.
    /// </summary>
    public class SymmetricContentCipher : ContentCipher
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricContentCipher"/> class with the specified encrypted data.
        /// </summary>
        /// <param name="data">The encrypted byte array.</param>
        public SymmetricContentCipher(byte[] data)
        {
            this.Data = data;
            this.ContentType = MediaTypes.SymmetricCipher;
        }
    }
}

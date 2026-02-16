namespace Bam.Encryption
{
    /// <summary>
    /// Represents a typed RSA asymmetric content cipher containing encrypted data with the asymmetric cipher content type.
    /// </summary>
    /// <typeparam name="TContent">The type of the original content that was encrypted.</typeparam>
    public class AsymmetricContentCipher<TContent> : ContentCipher<TContent>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricContentCipher{TContent}"/> class with the specified encrypted data.
        /// </summary>
        /// <param name="data">The encrypted byte array.</param>
        public AsymmetricContentCipher(byte[] data)
        {
            this.Data = data;
            this.ContentType = MediaTypes.AsymmetricCipher;
        }
    }
}

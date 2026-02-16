namespace Bam.Encryption
{
    /// <summary>
    /// Represents an RSA asymmetric content cipher containing encrypted data with the asymmetric cipher content type.
    /// </summary>
    public class RsaAsymmetricContentCipher : ContentCipher
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAsymmetricContentCipher"/> class with the specified encrypted data.
        /// </summary>
        /// <param name="data">The encrypted byte array.</param>
        public RsaAsymmetricContentCipher(byte[] data)
        {
            this.Data = data;
            this.ContentType = MediaTypes.AsymmetricCipher;
        }
    }
}

namespace Bam.Encryption
{
    /// <summary>
    /// Represents a cipher that carries content type metadata alongside the encrypted data.
    /// </summary>
    public interface IContentCipher
    {
        /// <summary>
        /// Gets the encrypted data as a byte array.
        /// </summary>
        byte[] Data { get; }

        /// <summary>
        /// Gets the media type indicating the encryption scheme used.
        /// </summary>
        string ContentType { get; }
    }
}

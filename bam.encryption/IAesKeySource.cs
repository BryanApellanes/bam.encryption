namespace Bam.Encryption
{
    /// <summary>
    /// Defines a source that can provide an AES key for symmetric encryption operations.
    /// </summary>
    public interface IAesKeySource
    {
        /// <summary>
        /// Get an aes key.
        /// </summary>
        /// <returns>AesKeyVectorPair</returns>
        AesKey GetAesKey();
    }
}

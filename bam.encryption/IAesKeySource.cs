namespace Bam.Encryption
{
    public interface IAesKeySource
    {
        /// <summary>
        /// Get an aes key.
        /// </summary>
        /// <returns>AesKeyVectorPair</returns>
        AesKey GetAesKey();
    }
}

namespace Bam.Encryption
{
    /// <summary>
    /// Defines a source that provides an RSA public key.
    /// </summary>
    public interface IRsaPublicKeySource
    {
        /// <summary>
        /// Gets the RSA public key.
        /// </summary>
        /// <returns>The RSA public key.</returns>
        RsaPublicKey GetRsaPublicKey();
    }
}

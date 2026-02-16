namespace Bam.Encryption
{
    /// <summary>
    /// Defines a source that provides an RSA public-private key pair.
    /// </summary>
    public interface IRsaKeySource : IRsaPublicKeySource
    {
        /// <summary>
        /// Gets the RSA public-private key pair.
        /// </summary>
        /// <returns>The RSA public-private key pair.</returns>
        RsaPublicPrivateKeyPair GetRsaKey();
    }
}

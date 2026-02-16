using Org.BouncyCastle.Security;

namespace Bam.Encryption
{
    /// <summary>
    /// Provides cryptographically secure random string generation utilities.
    /// </summary>
    public static class Secure
    {
        /// <summary>
        /// Generates a cryptographically secure random string by creating a random seed and computing its SHA-256 hash.
        /// </summary>
        /// <param name="seedLength">The length of the random seed in bytes; defaults to 64.</param>
        /// <returns>A SHA-256 hash of the Base64-encoded random seed.</returns>
        public static string RandomString(int seedLength = 64)
        {
            SecureRandom random = new SecureRandom();
            return random.GenerateSeed(seedLength).ToBase64().Sha256();
        }
    }
}

using Org.BouncyCastle.Security;

namespace Bam.Encryption
{
    public static class Secure
    {
        public static string RandomString(int seedLength = 64)
        {
            SecureRandom random = new SecureRandom();
            return random.GenerateSeed(seedLength).ToBase64().Sha256();
        }
    }
}

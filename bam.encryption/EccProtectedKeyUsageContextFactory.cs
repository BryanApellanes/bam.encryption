namespace Bam.Encryption;

public class EccProtectedKeyUsageContextFactory : IProtectedKeyUsageContextFactory
{
    public ProtectedKeyUsageContext Create(byte[] keyBytes)
    {
        return new EccPrivateKeyUsageContext(keyBytes);
    }
}

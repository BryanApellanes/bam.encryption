namespace Bam.Encryption;

/// <summary>
/// Creates <see cref="RsaPrivateKeyUsageContext"/> instances for RSA private key usage.
/// </summary>
public class RsaProtectedKeyUsageContextFactory : IProtectedKeyUsageContextFactory
{
    /// <inheritdoc />
    public ProtectedKeyUsageContext Create(byte[] keyBytes)
    {
        return new RsaPrivateKeyUsageContext(keyBytes);
    }
}

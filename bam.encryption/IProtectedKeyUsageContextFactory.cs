namespace Bam.Encryption;

/// <summary>
/// Creates <see cref="ProtectedKeyUsageContext"/> instances from raw key bytes.
/// </summary>
public interface IProtectedKeyUsageContextFactory
{
    /// <summary>
    /// Creates a protected key usage context for the specified key bytes.
    /// </summary>
    /// <param name="keyBytes">The raw key bytes.</param>
    /// <returns>A new <see cref="ProtectedKeyUsageContext"/>.</returns>
    ProtectedKeyUsageContext Create(byte[] keyBytes);
}

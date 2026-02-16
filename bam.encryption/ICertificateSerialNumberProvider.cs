using Org.BouncyCastle.Math;

namespace Bam.Encryption;

/// <summary>
/// Defines a provider that generates unique serial numbers for certificate generation.
/// </summary>
public interface ICertificateSerialNumberProvider
{
    /// <summary>
    /// Gets the next unique serial number for certificate generation.
    /// </summary>
    /// <returns>The next serial number as a <see cref="BigInteger"/>.</returns>
    BigInteger GetNextSerialNumber();
}
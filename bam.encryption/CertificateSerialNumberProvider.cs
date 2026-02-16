using Org.BouncyCastle.Math;

namespace Bam.Encryption;

/// <summary>
/// Provides incrementing serial numbers for certificate generation, starting from 1.
/// </summary>
public class CertificateSerialNumberProvider : ICertificateSerialNumberProvider
{
    private BigInteger _next;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSerialNumberProvider"/> class with a starting serial number of 1.
    /// </summary>
    public CertificateSerialNumberProvider()
    {
        _next = BigInteger.One;
    }

    /// <summary>
    /// Gets the next serial number and increments the internal counter.
    /// </summary>
    /// <returns>The next serial number as a <see cref="BigInteger"/>.</returns>
    public BigInteger GetNextSerialNumber()
    {
        BigInteger current = _next;
        BigInteger next = _next.Add(BigInteger.One);
        _next = next;
        return current;
    }
}
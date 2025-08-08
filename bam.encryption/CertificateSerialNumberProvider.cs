using Org.BouncyCastle.Math;

namespace Bam.Encryption;

public class CertificateSerialNumberProvider : ICertificateSerialNumberProvider
{
    private BigInteger _next;

    public CertificateSerialNumberProvider()
    {
        _next = BigInteger.One;
    }
    public BigInteger GetNextSerialNumber()
    {
        BigInteger current = _next;
        BigInteger next = _next.Add(BigInteger.One);
        _next = next;
        return current;
    }
}
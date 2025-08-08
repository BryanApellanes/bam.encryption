using Org.BouncyCastle.Math;

namespace Bam.Encryption;

public interface ICertificateSerialNumberProvider
{
    BigInteger GetNextSerialNumber();
}
using Org.BouncyCastle.X509;

namespace Bam.Encryption;

public class CertificateIssuerEventArgs : EventArgs
{
    public X509V3CertificateGenerator CertificateGenerator { get; set; }
    public ICertificateIssuer Issuer { get; set; }
    public X509Certificate Certificate { get; set; }
}
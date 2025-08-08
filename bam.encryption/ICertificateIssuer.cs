using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Bam.Encryption;
public interface ICertificateIssuer
{
    X509Certificate CreateCertificate(X509Name issuer, X509Name subject,
        AsymmetricKeyParameter issuerPrivate,
        AsymmetricKeyParameter subjectPublic);
}
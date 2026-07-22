using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;

namespace Bam.Encryption;
/// <summary>
/// Defines a component that creates X.509 certificates.
/// </summary>
public interface ICertificateIssuer
{
    /// <summary>
    /// Creates an X.509 certificate signed by the issuer's private key for the specified subject's public key.
    /// </summary>
    /// <param name="issuer">The distinguished name of the certificate issuer.</param>
    /// <param name="subject">The distinguished name of the certificate subject.</param>
    /// <param name="issuerPrivate">The issuer's private key used to sign the certificate.</param>
    /// <param name="subjectPublic">The subject's public key to include in the certificate.</param>
    /// <returns>The generated X.509 certificate.</returns>
    X509Certificate CreateCertificate(X509Name issuer, X509Name subject,
        AsymmetricKeyParameter issuerPrivate,
        AsymmetricKeyParameter subjectPublic);

    /// <summary>
    /// Creates an X.509 certificate signed by the issuer's private key for the specified subject's public key,
    /// applying the specified per-call issuance options for validity and BasicConstraints control.
    /// </summary>
    /// <param name="issuer">The distinguished name of the certificate issuer.</param>
    /// <param name="subject">The distinguished name of the certificate subject.</param>
    /// <param name="issuerPrivate">The issuer's private key used to sign the certificate.</param>
    /// <param name="subjectPublic">The subject's public key to include in the certificate.</param>
    /// <param name="options">The per-call issuance options controlling validity and CA status.</param>
    /// <returns>The generated X.509 certificate.</returns>
    X509Certificate CreateCertificate(X509Name issuer, X509Name subject,
        AsymmetricKeyParameter issuerPrivate,
        AsymmetricKeyParameter subjectPublic,
        CertificateIssuanceOptions options);
}

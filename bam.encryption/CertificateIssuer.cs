using System.Runtime.ConstrainedExecution;
using Bam.Logging;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;

namespace Bam.Encryption;


/// <summary>
/// Abstract base class for issuing X.509 certificates using either RSA or ECC key pairs with BouncyCastle.
/// </summary>
public abstract class CertificateIssuer : Loggable, ICertificateIssuer
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateIssuer"/> class with the specified serial number provider.
    /// </summary>
    /// <param name="serialNumberProvider">The provider used to generate unique serial numbers for certificates.</param>
    public CertificateIssuer(ICertificateSerialNumberProvider serialNumberProvider)
    {
        this.CertificateSerialNumberProvider = serialNumberProvider;
    }

    /// <summary>
    /// Gets the provider used to generate serial numbers for issued certificates.
    /// </summary>
    public ICertificateSerialNumberProvider CertificateSerialNumberProvider { get; private set; }

    /// <summary>
    /// Gets or sets the duration for which issued certificates are valid.
    /// </summary>
    public TimeSpan ValidFor { get; set; }

    protected event EventHandler<CertificateIssuerEventArgs> BeforeCertificateGenerated;
    protected event EventHandler<CertificateIssuerEventArgs> AfterCertificateGenerated;

    /// <summary>
    /// Creates an X.509 certificate signed by the issuer's private key for the specified subject's public key. Automatically selects ECDSA or RSA signature based on the issuer key type.
    /// </summary>
    /// <param name="issuer">The distinguished name of the certificate issuer.</param>
    /// <param name="subject">The distinguished name of the certificate subject.</param>
    /// <param name="issuerPrivate">The issuer's private key used to sign the certificate.</param>
    /// <param name="subjectPublic">The subject's public key to include in the certificate.</param>
    /// <returns>The generated X.509 certificate.</returns>
    public X509Certificate CreateCertificate(X509Name issuer, X509Name subject,
        AsymmetricKeyParameter issuerPrivate,
        AsymmetricKeyParameter subjectPublic)
    {
        ISignatureFactory signatureFactory;
        if (issuerPrivate is ECPrivateKeyParameters)
        {
            signatureFactory = new Asn1SignatureFactory(
                X9ObjectIdentifiers.ECDsaWithSha256.ToString(), 
                issuerPrivate);
        }
        else
        {
            signatureFactory = new Asn1SignatureFactory(
                PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), 
                issuerPrivate);
        }

        X509V3CertificateGenerator certGenerator = CreateCertificateGenerator(issuer, subject, subjectPublic);

        FireEvent(BeforeCertificateGenerated, new CertificateIssuerEventArgs(){ Issuer = this, CertificateGenerator = certGenerator});
        X509Certificate certificate = certGenerator.Generate(signatureFactory);
        FireEvent(AfterCertificateGenerated, new CertificateIssuerEventArgs(){ Issuer = this, CertificateGenerator = certGenerator, Certificate = certificate});
        return certificate;
    }

    protected virtual X509V3CertificateGenerator CreateCertificateGenerator(X509Name issuer, X509Name subject,
        AsymmetricKeyParameter subjectPublic)
    {
        var certGenerator = new X509V3CertificateGenerator();
        certGenerator.SetIssuerDN(issuer);
        certGenerator.SetSubjectDN(subject);
        certGenerator.SetSerialNumber(CertificateSerialNumberProvider.GetNextSerialNumber());
        certGenerator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        certGenerator.SetNotBefore(DateTime.UtcNow);
        certGenerator.SetPublicKey(subjectPublic);
        certGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(true));
        return certGenerator;
    }
}
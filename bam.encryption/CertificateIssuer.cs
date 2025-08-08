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


public abstract class CertificateIssuer : Loggable, ICertificateIssuer
{
    public CertificateIssuer(ICertificateSerialNumberProvider serialNumberProvider)
    {
        this.CertificateSerialNumberProvider = serialNumberProvider;
    }

    public ICertificateSerialNumberProvider CertificateSerialNumberProvider { get; private set; }

    public TimeSpan ValidFor { get; set; }

    protected event EventHandler<CertificateIssuerEventArgs> BeforeCertificateGenerated;
    protected event EventHandler<CertificateIssuerEventArgs> AfterCertificateGenerated;
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
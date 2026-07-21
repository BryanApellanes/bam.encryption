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
    /// Gets or sets the default duration for which issued certificates are valid, applied when a call
    /// supplies no <see cref="CertificateIssuanceOptions.ValidFor"/> override. <see cref="TimeSpan.Zero"/>
    /// means unset: validity falls back to one calendar year from the moment of issuance. A negative
    /// value causes certificate creation to throw <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    public TimeSpan ValidFor { get; set; }

    protected event EventHandler<CertificateIssuerEventArgs> BeforeCertificateGenerated = null!;
    protected event EventHandler<CertificateIssuerEventArgs> AfterCertificateGenerated = null!;

    /// <summary>
    /// Creates an X.509 certificate signed by the issuer's private key for the specified subject's public key,
    /// preserving historical defaults: a certificate authority certificate whose validity resolves from
    /// <see cref="ValidFor"/> (one calendar year when unset). Automatically selects ECDSA or RSA signature
    /// based on the issuer key type.
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
        return CreateCertificate(issuer, subject, issuerPrivate, subjectPublic, CertificateIssuanceOptions.Default());
    }

    /// <summary>
    /// Creates an X.509 certificate signed by the issuer's private key for the specified subject's public key,
    /// applying the specified per-call issuance options for validity and BasicConstraints control.
    /// Automatically selects ECDSA or RSA signature based on the issuer key type. The
    /// <see cref="BeforeCertificateGenerated"/> event fires after the generator is fully configured
    /// (extensions included), immediately before the certificate is generated.
    /// </summary>
    /// <param name="issuer">The distinguished name of the certificate issuer.</param>
    /// <param name="subject">The distinguished name of the certificate subject.</param>
    /// <param name="issuerPrivate">The issuer's private key used to sign the certificate.</param>
    /// <param name="subjectPublic">The subject's public key to include in the certificate.</param>
    /// <param name="options">The per-call issuance options controlling validity and CA status.</param>
    /// <returns>The generated X.509 certificate.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <see cref="CertificateIssuanceOptions.PathLengthConstraint"/> is set while <see cref="CertificateIssuanceOptions.IsCertificateAuthority"/> is false.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the supplied or configured validity is invalid.</exception>
    public X509Certificate CreateCertificate(X509Name issuer, X509Name subject,
        AsymmetricKeyParameter issuerPrivate,
        AsymmetricKeyParameter subjectPublic,
        CertificateIssuanceOptions options)
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

        X509V3CertificateGenerator certGenerator = CreateCertificateGenerator(issuer, subject, subjectPublic, options);

        FireEvent(BeforeCertificateGenerated, new CertificateIssuerEventArgs(){ Issuer = this, CertificateGenerator = certGenerator});
        X509Certificate certificate = certGenerator.Generate(signatureFactory);
        FireEvent(AfterCertificateGenerated, new CertificateIssuerEventArgs(){ Issuer = this, CertificateGenerator = certGenerator, Certificate = certificate});
        return certificate;
    }

    /// <summary>
    /// Creates and configures the certificate generator for the specified issuance: validates the options,
    /// captures a single UTC instant, sets NotBefore then NotAfter from the resolved validity, and adds a
    /// critical BasicConstraints extension per the options.
    /// </summary>
    /// <param name="issuer">The distinguished name of the certificate issuer.</param>
    /// <param name="subject">The distinguished name of the certificate subject.</param>
    /// <param name="subjectPublic">The subject's public key to include in the certificate.</param>
    /// <param name="options">The per-call issuance options controlling validity and CA status.</param>
    /// <returns>The configured certificate generator.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">Thrown when <see cref="CertificateIssuanceOptions.PathLengthConstraint"/> is set while <see cref="CertificateIssuanceOptions.IsCertificateAuthority"/> is false (RFC 5280 section 4.2.1.9).</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <see cref="CertificateIssuanceOptions.ValidFor"/> is non-positive, or the instance <see cref="ValidFor"/> is negative.</exception>
    protected virtual X509V3CertificateGenerator CreateCertificateGenerator(X509Name issuer, X509Name subject,
        AsymmetricKeyParameter subjectPublic, CertificateIssuanceOptions options)
    {
        if (options == null)
        {
            throw new ArgumentNullException(nameof(options));
        }
        if (options.PathLengthConstraint.HasValue && !options.IsCertificateAuthority)
        {
            throw new ArgumentException(
                "PathLengthConstraint requires IsCertificateAuthority: RFC 5280 section 4.2.1.9 forbids pathLenConstraint without the cA boolean.",
                nameof(options));
        }
        if (options.ValidFor.HasValue && options.ValidFor.Value <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(options),
                "CertificateIssuanceOptions.ValidFor must be positive when set.");
        }
        if (this.ValidFor < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(ValidFor),
                "ValidFor must not be negative: TimeSpan.Zero means unset (one calendar year).");
        }

        DateTime notBefore = DateTime.UtcNow;
        DateTime notAfter = ResolveNotAfter(notBefore, options);

        X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
        certGenerator.SetIssuerDN(issuer);
        certGenerator.SetSubjectDN(subject);
        certGenerator.SetSerialNumber(CertificateSerialNumberProvider.GetNextSerialNumber());
        certGenerator.SetNotBefore(notBefore);
        certGenerator.SetNotAfter(notAfter);
        certGenerator.SetPublicKey(subjectPublic);
        certGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, CreateBasicConstraints(options));
        return certGenerator;
    }

    private DateTime ResolveNotAfter(DateTime notBefore, CertificateIssuanceOptions options)
    {
        if (options.ValidFor.HasValue)
        {
            return notBefore.Add(options.ValidFor.Value);
        }
        if (this.ValidFor > TimeSpan.Zero)
        {
            return notBefore.Add(this.ValidFor);
        }
        return notBefore.AddYears(1);
    }

    private static BasicConstraints CreateBasicConstraints(CertificateIssuanceOptions options)
    {
        if (!options.IsCertificateAuthority)
        {
            return new BasicConstraints(false);
        }
        if (options.PathLengthConstraint.HasValue)
        {
            return new BasicConstraints(options.PathLengthConstraint.Value);
        }
        return new BasicConstraints(true);
    }
}

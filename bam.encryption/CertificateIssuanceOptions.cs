namespace Bam.Encryption;

/// <summary>
/// Carries per-call issuance policy for a single certificate: an optional validity override,
/// whether the certificate is a certificate authority, and an optional path length constraint.
/// Construct via <see cref="Default"/> or <see cref="EndEntity"/>; each returns a fresh instance
/// per call, so options are never shared between call sites.
/// </summary>
public class CertificateIssuanceOptions
{
    /// <summary>
    /// Gets or sets the validity period for the issued certificate. When null, the issuer's
    /// <see cref="CertificateIssuer.ValidFor"/> applies, falling back to one calendar year when
    /// that is unset (<see cref="TimeSpan.Zero"/>). A non-positive value causes certificate
    /// creation to throw <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    public TimeSpan? ValidFor { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether the issued certificate is a certificate authority.
    /// Defaults to true, matching historical issuer behavior.
    /// </summary>
    public bool IsCertificateAuthority { get; set; } = true;

    /// <summary>
    /// Gets or sets the BasicConstraints path length constraint. Only meaningful when
    /// <see cref="IsCertificateAuthority"/> is true: RFC 5280 section 4.2.1.9 forbids
    /// pathLenConstraint without the cA boolean, so setting this on a non-CA issuance causes
    /// certificate creation to throw <see cref="ArgumentException"/>.
    /// </summary>
    public int? PathLengthConstraint { get; set; }

    /// <summary>
    /// Creates options preserving historical issuer defaults: a certificate authority certificate
    /// with issuer-resolved validity. Returns a fresh instance per call.
    /// </summary>
    /// <returns>A new <see cref="CertificateIssuanceOptions"/> instance.</returns>
    public static CertificateIssuanceOptions Default()
    {
        return new CertificateIssuanceOptions();
    }

    /// <summary>
    /// Creates options for an end-entity (leaf) certificate that is not a certificate authority.
    /// Returns a fresh instance per call.
    /// </summary>
    /// <returns>A new <see cref="CertificateIssuanceOptions"/> instance with <see cref="IsCertificateAuthority"/> false.</returns>
    public static CertificateIssuanceOptions EndEntity()
    {
        return new CertificateIssuanceOptions { IsCertificateAuthority = false };
    }

    /// <summary>
    /// Sets <see cref="ValidFor"/> and returns this instance.
    /// </summary>
    /// <param name="validFor">The validity period for the issued certificate.</param>
    /// <returns>This instance.</returns>
    public CertificateIssuanceOptions WithValidFor(TimeSpan validFor)
    {
        this.ValidFor = validFor;
        return this;
    }
}

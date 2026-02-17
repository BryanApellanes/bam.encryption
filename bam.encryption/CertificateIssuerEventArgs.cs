using Org.BouncyCastle.X509;

namespace Bam.Encryption;

/// <summary>
/// Provides data for certificate issuer events, containing the certificate generator, issuer, and the generated certificate.
/// </summary>
public class CertificateIssuerEventArgs : EventArgs
{
    /// <summary>
    /// Gets or sets the certificate generator used to create the certificate.
    /// </summary>
    public X509V3CertificateGenerator CertificateGenerator { get; set; } = null!;

    /// <summary>
    /// Gets or sets the certificate issuer that raised the event.
    /// </summary>
    public ICertificateIssuer Issuer { get; set; } = null!;

    /// <summary>
    /// Gets or sets the generated certificate. This is null in before-generation events.
    /// </summary>
    public X509Certificate Certificate { get; set; } = null!;
}
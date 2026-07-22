namespace Bam.Encryption.Tests.TestClasses;

/// <summary>
/// Minimal concrete <see cref="CertificateIssuer"/> for exercising base-class issuance behavior in tests.
/// </summary>
public class TestCertificateIssuer : CertificateIssuer
{
    public TestCertificateIssuer(ICertificateSerialNumberProvider serialNumberProvider) : base(serialNumberProvider)
    {
    }
}

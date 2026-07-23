using Bam.Encryption.Tests.TestClasses;
using Bam.Test;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("CertificateIssuerShould", Selector = "cish")]
public class CertificateIssuerShould : UnitTestMenuContainer
{
    private const string BasicConstraintsOid = "2.5.29.19";

    [UnitTest]
    public void DefaultsPreserveCurrentBehavior()
    {
        After.Setup(reg =>
        {
            reg.Set(new TestCertificateIssuer(new CertificateSerialNumberProvider()));
        })
        .When<TestCertificateIssuer>("issues a certificate through the legacy four argument overload", (issuer, reg) =>
        {
            using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            EccPrivateKey privateKey = new EccPrivateKey(keyPair);
            EccPublicKey publicKey = keyPair.GetEccPublicKey();
            X509Name name = new X509Name("CN=Default Behavior Test");
            DateTime preCallUtc = DateTime.UtcNow;
            X509Certificate certificate = issuer.CreateCertificate(name, name, privateKey.Value, publicKey.Value);
            return new IssuedCertificateOutcome(certificate, preCallUtc);
        })
        .TheTest
        .ShouldPass(because =>
        {
            IssuedCertificateOutcome outcome = because.ResultAs<IssuedCertificateOutcome>();
            because.ItsTrue("certificate is a certificate authority", outcome.Certificate.GetBasicConstraints() != -1);
            because.ItsTrue("BasicConstraints extension is critical", outcome.Certificate.GetCriticalExtensionOids().Contains(BasicConstraintsOid));
            because.ItsTrue("NotBefore is at or after the pre-call instant less clock granularity",
                outcome.Certificate.NotBefore >= outcome.PreCallUtc.AddSeconds(-2));
            because.ItsTrue("NotBefore is within thirty seconds of the pre-call instant",
                (outcome.Certificate.NotBefore - outcome.PreCallUtc).Duration() <= TimeSpan.FromSeconds(30));
            because.ItsTrue("NotAfter equals NotBefore plus one calendar year",
                (outcome.Certificate.NotAfter - outcome.Certificate.NotBefore.AddYears(1)).Duration() <= TimeSpan.FromSeconds(1));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void HonorsInstanceValidFor()
    {
        After.Setup(reg =>
        {
            reg.Set(new TestCertificateIssuer(new CertificateSerialNumberProvider()));
        })
        .When<TestCertificateIssuer>("issues with instance ValidFor of thirty days", (issuer, reg) =>
        {
            issuer.ValidFor = TimeSpan.FromDays(30);
            using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            EccPrivateKey privateKey = new EccPrivateKey(keyPair);
            EccPublicKey publicKey = keyPair.GetEccPublicKey();
            X509Name name = new X509Name("CN=Instance ValidFor Test");
            return issuer.CreateCertificate(name, name, privateKey.Value, publicKey.Value);
        })
        .TheTest
        .ShouldPass(because =>
        {
            X509Certificate certificate = because.ResultAs<X509Certificate>();
            because.ItsTrue("validity spans thirty days",
                ((certificate.NotAfter - certificate.NotBefore) - TimeSpan.FromDays(30)).Duration() <= TimeSpan.FromSeconds(1));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void PerCallValidForOverridesInstance()
    {
        After.Setup(reg =>
        {
            reg.Set(new TestCertificateIssuer(new CertificateSerialNumberProvider()));
        })
        .When<TestCertificateIssuer>("issues with options ValidFor of ten days over instance thirty", (issuer, reg) =>
        {
            issuer.ValidFor = TimeSpan.FromDays(30);
            using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            EccPrivateKey privateKey = new EccPrivateKey(keyPair);
            EccPublicKey publicKey = keyPair.GetEccPublicKey();
            X509Name name = new X509Name("CN=Per Call Override Test");
            CertificateIssuanceOptions options = CertificateIssuanceOptions.Default().WithValidFor(TimeSpan.FromDays(10));
            return issuer.CreateCertificate(name, name, privateKey.Value, publicKey.Value, options);
        })
        .TheTest
        .ShouldPass(because =>
        {
            X509Certificate certificate = because.ResultAs<X509Certificate>();
            because.ItsTrue("validity spans ten days, not thirty",
                ((certificate.NotAfter - certificate.NotBefore) - TimeSpan.FromDays(10)).Duration() <= TimeSpan.FromSeconds(1));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void EndEntityOptionsYieldNonCaCertificate()
    {
        After.Setup(reg =>
        {
            reg.Set(new TestCertificateIssuer(new CertificateSerialNumberProvider()));
        })
        .When<TestCertificateIssuer>("issues an end entity certificate", (issuer, reg) =>
        {
            using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            EccPrivateKey privateKey = new EccPrivateKey(keyPair);
            EccPublicKey publicKey = keyPair.GetEccPublicKey();
            X509Name name = new X509Name("CN=End Entity Test");
            return issuer.CreateCertificate(name, name, privateKey.Value, publicKey.Value, CertificateIssuanceOptions.EndEntity());
        })
        .TheTest
        .ShouldPass(because =>
        {
            X509Certificate certificate = because.ResultAs<X509Certificate>();
            because.ItsTrue("certificate is not a certificate authority", certificate.GetBasicConstraints() == -1);
            because.ItsTrue("BasicConstraints extension is present and critical",
                certificate.GetCriticalExtensionOids().Contains(BasicConstraintsOid));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void PathLengthConstraintIsEmitted()
    {
        After.Setup(reg =>
        {
            reg.Set(new TestCertificateIssuer(new CertificateSerialNumberProvider()));
        })
        .When<TestCertificateIssuer>("issues a CA certificate with path length zero", (issuer, reg) =>
        {
            using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            EccPrivateKey privateKey = new EccPrivateKey(keyPair);
            EccPublicKey publicKey = keyPair.GetEccPublicKey();
            X509Name name = new X509Name("CN=Path Length Test");
            CertificateIssuanceOptions options = CertificateIssuanceOptions.Default();
            options.PathLengthConstraint = 0;
            return issuer.CreateCertificate(name, name, privateKey.Value, publicKey.Value, options);
        })
        .TheTest
        .ShouldPass(because =>
        {
            X509Certificate certificate = because.ResultAs<X509Certificate>();
            because.ItsTrue("BasicConstraints path length is zero", certificate.GetBasicConstraints() == 0);
            because.ItsTrue("BasicConstraints extension is critical",
                certificate.GetCriticalExtensionOids().Contains(BasicConstraintsOid));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void NonPositiveOptionsValidForThrows()
    {
        After.Setup(reg =>
        {
            reg.Set(new TestCertificateIssuer(new CertificateSerialNumberProvider()));
        })
        .When<TestCertificateIssuer>("issues with zero and negative options ValidFor", (issuer, reg) =>
        {
            using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            EccPrivateKey privateKey = new EccPrivateKey(keyPair);
            EccPublicKey publicKey = keyPair.GetEccPublicKey();
            X509Name name = new X509Name("CN=Non Positive Options Test");
            Exception? zeroThrown = Catch(() => issuer.CreateCertificate(name, name, privateKey.Value, publicKey.Value,
                CertificateIssuanceOptions.Default().WithValidFor(TimeSpan.Zero)));
            Exception? negativeThrown = Catch(() => issuer.CreateCertificate(name, name, privateKey.Value, publicKey.Value,
                CertificateIssuanceOptions.Default().WithValidFor(TimeSpan.FromDays(-1))));
            return new ValidityThrowOutcome(zeroThrown, negativeThrown);
        })
        .TheTest
        .ShouldPass(because =>
        {
            ValidityThrowOutcome outcome = because.ResultAs<ValidityThrowOutcome>();
            because.ItsTrue("zero options ValidFor threw ArgumentOutOfRangeException",
                outcome.ZeroThrown is ArgumentOutOfRangeException);
            because.ItsTrue("negative options ValidFor threw ArgumentOutOfRangeException",
                outcome.NegativeThrown is ArgumentOutOfRangeException);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void PathLengthWithoutCaThrows()
    {
        After.Setup(reg =>
        {
            reg.Set(new TestCertificateIssuer(new CertificateSerialNumberProvider()));
        })
        .When<TestCertificateIssuer>("issues an end entity certificate carrying a path length", (issuer, reg) =>
        {
            using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            EccPrivateKey privateKey = new EccPrivateKey(keyPair);
            EccPublicKey publicKey = keyPair.GetEccPublicKey();
            X509Name name = new X509Name("CN=Path Length Without CA Test");
            CertificateIssuanceOptions options = CertificateIssuanceOptions.EndEntity();
            options.PathLengthConstraint = 1;
            return new CaughtExceptionOutcome(Catch(() =>
                issuer.CreateCertificate(name, name, privateKey.Value, publicKey.Value, options)));
        })
        .TheTest
        .ShouldPass(because =>
        {
            CaughtExceptionOutcome outcome = because.ResultAs<CaughtExceptionOutcome>();
            because.ItsTrue("an exception was thrown", outcome.Thrown != null);
            because.ItsTrue("the exception is exactly ArgumentException",
                outcome.Thrown != null && outcome.Thrown.GetType() == typeof(ArgumentException));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void NegativeInstanceValidForThrows()
    {
        After.Setup(reg =>
        {
            reg.Set(new TestCertificateIssuer(new CertificateSerialNumberProvider()));
        })
        .When<TestCertificateIssuer>("issues with negative then zero instance ValidFor", (issuer, reg) =>
        {
            using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            EccPrivateKey privateKey = new EccPrivateKey(keyPair);
            EccPublicKey publicKey = keyPair.GetEccPublicKey();
            X509Name name = new X509Name("CN=Negative Instance ValidFor Test");
            issuer.ValidFor = TimeSpan.FromDays(-30);
            Exception? negativeThrown = Catch(() => issuer.CreateCertificate(name, name, privateKey.Value, publicKey.Value));
            issuer.ValidFor = TimeSpan.Zero;
            X509Certificate zeroSentinelCertificate = issuer.CreateCertificate(name, name, privateKey.Value, publicKey.Value);
            return new InstanceValidForOutcome(negativeThrown, zeroSentinelCertificate);
        })
        .TheTest
        .ShouldPass(because =>
        {
            InstanceValidForOutcome outcome = because.ResultAs<InstanceValidForOutcome>();
            because.ItsTrue("negative instance ValidFor threw ArgumentOutOfRangeException",
                outcome.NegativeThrown is ArgumentOutOfRangeException);
            because.ItsTrue("zero instance ValidFor still issues a one calendar year certificate",
                (outcome.ZeroSentinelCertificate.NotAfter - outcome.ZeroSentinelCertificate.NotBefore.AddYears(1)).Duration() <= TimeSpan.FromSeconds(1));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static Exception? Catch(Action action)
    {
        try
        {
            action();
            return null;
        }
        catch (Exception ex)
        {
            return ex;
        }
    }

    private sealed record IssuedCertificateOutcome(X509Certificate Certificate, DateTime PreCallUtc);

    private sealed record ValidityThrowOutcome(Exception? ZeroThrown, Exception? NegativeThrown);

    private sealed record CaughtExceptionOutcome(Exception? Thrown);

    private sealed record InstanceValidForOutcome(Exception? NegativeThrown, X509Certificate ZeroSentinelCertificate);
}

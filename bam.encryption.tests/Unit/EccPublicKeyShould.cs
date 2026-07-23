using Bam.Test;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("EccPublicKeyShould", Selector = "epubks")]
public class EccPublicKeyShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ExposePopulatedKeyThroughAllReferenceTypes()
    {
        After.Setup(reg =>
        {
            reg.Set(new EccPublicPrivateKeyPair());
        })
        .When<EccPublicPrivateKeyPair>("reads the key value through concrete, base and interface references", (keyPair, reg) =>
        {
            EccPublicKey concrete = keyPair.GetEccPublicKey();
            PublicKey baseTyped = concrete;
            IPublicKey interfaceTyped = concrete;
            return new KeyValueReadOutcome(concrete.Value, baseTyped.Value, interfaceTyped.Value, concrete.EcValue);
        })
        .TheTest
        .ShouldPass(because =>
        {
            KeyValueReadOutcome outcome = because.ResultAs<KeyValueReadOutcome>();
            because.ItsTrue("concrete-typed Value read is populated", outcome.ConcreteValue != null);
            because.ItsTrue("base-typed Value read is populated", outcome.BaseValue != null);
            because.ItsTrue("interface-typed Value read is populated", outcome.InterfaceValue != null);
            because.ItsTrue("concrete-typed read returns the same key as the base-typed read", ReferenceEquals(outcome.ConcreteValue, outcome.BaseValue));
            because.ItsTrue("interface-typed read returns the same key as the base-typed read", ReferenceEquals(outcome.InterfaceValue, outcome.BaseValue));
            because.ItsTrue("EcValue returns the same key as Value typed as ECPublicKeyParameters", ReferenceEquals(outcome.EcValue, outcome.ConcreteValue));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ConvertToPemStringImplicitly()
    {
        After.Setup(reg =>
        {
            reg.Set(new EccPublicPrivateKeyPair());
        })
        .When<EccPublicPrivateKeyPair>("converts the public key to a PEM string and back", (keyPair, reg) =>
        {
            EccPublicKey publicKey = keyPair.GetEccPublicKey();
            string pem = publicKey;
            EccPublicKey roundTripped = new EccPublicKey(pem);
            return new PemConversionOutcome(publicKey, pem, roundTripped);
        })
        .TheTest
        .ShouldPass(because =>
        {
            PemConversionOutcome outcome = because.ResultAs<PemConversionOutcome>();
            because.ItsTrue("implicit conversion produced a non-empty string", !string.IsNullOrWhiteSpace(outcome.Pem));
            because.ItsTrue("implicit conversion result is a public key PEM", outcome.Pem.Contains("BEGIN PUBLIC KEY"));
            because.ItsTrue("implicit conversion matches the Pem property", outcome.Pem.Equals(outcome.Original.Pem));
            because.ItsTrue("round-tripped key equals the original key", outcome.RoundTripped.EcValue.Equals(outcome.Original.EcValue));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record KeyValueReadOutcome(
        AsymmetricKeyParameter ConcreteValue,
        AsymmetricKeyParameter BaseValue,
        AsymmetricKeyParameter InterfaceValue,
        ECPublicKeyParameters EcValue);

    private sealed record PemConversionOutcome(
        EccPublicKey Original,
        string Pem,
        EccPublicKey RoundTripped);
}

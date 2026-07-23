using Bam.Test;
using Org.BouncyCastle.Crypto;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("RsaPublicKeyShould", Selector = "rpubks")]
public class RsaPublicKeyShould : UnitTestMenuContainer
{
    [UnitTest]
    public void DerivePemFromKeyMaterialRatherThanStoreCtorInput()
    {
        After.Setup(reg =>
        {
            reg.Set(new RsaPublicPrivateKeyPair());
        })
        .When<RsaPublicPrivateKeyPair>("constructs from a non-normalized PEM and reads Pem through concrete and base references", (keyPair, reg) =>
        {
            string nonNormalizedPem = "\n" + keyPair.PublicKeyPem + "\n\n";
            RsaPublicKey concrete = new RsaPublicKey(nonNormalizedPem);
            PublicKey baseTyped = concrete;
            return new PemReadOutcome(concrete, nonNormalizedPem, concrete.Pem, baseTyped.Pem);
        })
        .TheTest
        .ShouldPass(because =>
        {
            PemReadOutcome outcome = because.ResultAs<PemReadOutcome>();
            because.ItsTrue("concrete-typed Pem read is populated", !string.IsNullOrWhiteSpace(outcome.ConcretePem));
            because.ItsTrue("concrete-typed and base-typed Pem reads agree", outcome.ConcretePem.Equals(outcome.BasePem));
            because.ItsTrue("Pem is the canonical encoding of the key material", outcome.ConcretePem.Equals(outcome.PublicKey.Value.ToPem()));
            because.ItsTrue("Pem differs from the non-normalized constructor input", !outcome.ConcretePem.Equals(outcome.NonNormalizedInput));
            because.ItsTrue("Pem parses back to the key material", outcome.PublicKey.Pem.PemToKey().Equals(outcome.PublicKey.Value));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record PemReadOutcome(
        RsaPublicKey PublicKey,
        string NonNormalizedInput,
        string ConcretePem,
        string BasePem);
}

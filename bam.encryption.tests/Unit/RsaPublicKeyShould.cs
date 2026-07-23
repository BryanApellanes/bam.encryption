using Bam.Test;
using Org.BouncyCastle.Crypto;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("RsaPublicKeyShould", Selector = "rpubks")]
public class RsaPublicKeyShould : UnitTestMenuContainer
{
    [UnitTest]
    public void ExposeSinglePemDerivedFromKeyMaterial()
    {
        After.Setup(reg =>
        {
            reg.Set(new RsaPublicPrivateKeyPair());
        })
        .When<RsaPublicPrivateKeyPair>("reads Pem through concrete and base references", (keyPair, reg) =>
        {
            RsaPublicKey concrete = keyPair.GetRsaPublicKey();
            PublicKey baseTyped = concrete;
            return new PemReadOutcome(concrete, concrete.Pem, baseTyped.Pem);
        })
        .TheTest
        .ShouldPass(because =>
        {
            PemReadOutcome outcome = because.ResultAs<PemReadOutcome>();
            because.ItsTrue("concrete-typed Pem read is populated", !string.IsNullOrWhiteSpace(outcome.ConcretePem));
            because.ItsTrue("concrete-typed and base-typed Pem reads agree", outcome.ConcretePem.Equals(outcome.BasePem));
            because.ItsTrue("Pem parses back to the key material", outcome.PublicKey.Pem.PemToKey().Equals(outcome.PublicKey.Value));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record PemReadOutcome(
        RsaPublicKey PublicKey,
        string ConcretePem,
        string BasePem);
}

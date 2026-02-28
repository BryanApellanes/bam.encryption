using Bam.Test;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("EccPrivateKeyShould", Selector = "epks")]
public class EccPrivateKeyShould : UnitTestMenuContainer
{
    [UnitTest]
    public void SignAndVerifyRoundTrip()
    {
        string testData = 64.RandomLetters();

        After.Setup(reg =>
        {
            EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            reg.Set(new EccPrivateKey(keyPair));
            reg.Set(keyPair.GetEccPublicKey());
        })
        .When<EccPrivateKey>("signs string and verifies with public key", (pk, reg) =>
        {
            ISignature signature = pk.Sign(testData);
            return reg.Get<EccPublicKey>().Verify(signature);
        })
        .TheTest
        .ShouldPass(because =>
        {
            ISignatureVerification verification = because.ResultAs<ISignatureVerification>();
            because.ItsTrue("signed data matches original", testData.Equals(verification.Signature.Data));
            because.ItsTrue("signature verified", verification.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SignBytesAndVerifyRoundTrip()
    {
        byte[] testBytes = System.Text.Encoding.UTF8.GetBytes(64.RandomLetters());

        After.Setup(reg =>
        {
            EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            reg.Set(new EccPrivateKey(keyPair));
            reg.Set(keyPair.GetEccPublicKey());
        })
        .When<EccPrivateKey>("signs bytes and verifies with public key", (pk, reg) =>
        {
            ISignature signature = pk.Sign(testBytes);
            return reg.Get<EccPublicKey>().Verify(signature);
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("signature verified", because.ResultAs<ISignatureVerification>().Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

using Bam.Test;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("EccPrivateKeyShould", Selector = "epks")]
public class EccPrivateKeyShould : UnitTestMenuContainer
{
    [UnitTest]
    public void SignAndVerifyRoundTrip()
    {
        using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
        EccPrivateKey privateKey = new EccPrivateKey(keyPair);
        EccPublicKey publicKey = keyPair.GetEccPublicKey();
        string testData = 64.RandomLetters();

        When.A<EccPrivateKey>("signs string and verifies with public key",
            privateKey,
            (pk) =>
            {
                ISignature signature = pk.Sign(testData);
                return publicKey.Verify(signature);
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
        using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
        EccPrivateKey privateKey = new EccPrivateKey(keyPair);
        EccPublicKey publicKey = keyPair.GetEccPublicKey();
        byte[] testBytes = System.Text.Encoding.UTF8.GetBytes(64.RandomLetters());

        When.A<EccPrivateKey>("signs bytes and verifies with public key",
            privateKey,
            (pk) =>
            {
                ISignature signature = pk.Sign(testBytes);
                return publicKey.Verify(signature);
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

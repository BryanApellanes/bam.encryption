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
                ISignatureVerification verification = publicKey.Verify(signature);
                return new object[] { signature.Data, verification.Success };
            })
        .TheTest
        .ShouldPass(because =>
        {
            object[] results = (object[])because.Result;
            string signedData = (string)results[0];
            bool verified = (bool)results[1];
            because.ItsTrue("signed data matches original", testData.Equals(signedData));
            because.ItsTrue("signature verified", verified);
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
                ISignatureVerification verification = publicKey.Verify(signature);
                return verification.Success;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("signature verified", (bool)because.Result);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

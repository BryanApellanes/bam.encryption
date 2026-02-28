using Bam.Test;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("EccPrivateKeyUsageContextShould", Selector = "epkucs")]
public class EccPrivateKeyUsageContextShould : UnitTestMenuContainer
{
    private static byte[] GetEccPemBytes(EccPublicPrivateKeyPair keyPair)
    {
        using EccPrivateKey privateKey = new EccPrivateKey(keyPair);
        return (byte[])privateKey.Pem.Clone();
    }

    [UnitTest]
    public void UseKeyExecutesActionWithEccPrivateKey()
    {
        using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
        EccPublicKey publicKey = keyPair.GetEccPublicKey();
        byte[] pemBytes = GetEccPemBytes(keyPair);
        string testData = 64.RandomLetters();

        bool isEccPrivateKey = false;

        When.A<EccPrivateKeyUsageContext>("executes action with ECC private key",
            new EccPrivateKeyUsageContext(pemBytes),
            (context) =>
            {
                ISignature? signature = null;
                context.UseKey(privateKey =>
                {
                    isEccPrivateKey = privateKey is EccPrivateKey;
                    signature = privateKey.Sign(testData);
                });
                return publicKey.Verify(signature!);
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("key is EccPrivateKey", isEccPrivateKey);
            because.ItsTrue("signature verified", because.ResultAs<ISignatureVerification>().Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SignWithKeyStringReturnsValidSignature()
    {
        using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
        EccPublicKey publicKey = keyPair.GetEccPublicKey();
        byte[] pemBytes = GetEccPemBytes(keyPair);
        string testData = 64.RandomLetters();

        When.A<EccPrivateKeyUsageContext>("signs string with protected key and verifies",
            new EccPrivateKeyUsageContext(pemBytes),
            (context) =>
            {
                ISignature signature = context.SignWithKey(testData);
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
    public void SignWithKeyBytesReturnsValidSignature()
    {
        using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
        EccPublicKey publicKey = keyPair.GetEccPublicKey();
        byte[] pemBytes = GetEccPemBytes(keyPair);
        byte[] testBytes = System.Text.Encoding.UTF8.GetBytes(64.RandomLetters());

        When.A<EccPrivateKeyUsageContext>("signs bytes with protected key and verifies",
            new EccPrivateKeyUsageContext(pemBytes),
            (context) =>
            {
                ISignature signature = context.SignWithKey(testBytes);
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

    [UnitTest]
    public void DisposesClearsCipherBytes()
    {
        using EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
        byte[] pemBytes = GetEccPemBytes(keyPair);

        When.A<EccPrivateKeyUsageContext>("clears cipher bytes on dispose",
            new EccPrivateKeyUsageContext(pemBytes),
            (context) =>
            {
                context.Dispose();
                bool threw = false;
                try
                {
                    context.UseKey(_ => { });
                }
                catch
                {
                    threw = true;
                }
                return threw;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("using disposed context throws or fails", because.ResultAs<bool>());
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

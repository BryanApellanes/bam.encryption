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

        When.A<EccPrivateKeyUsageContext>("executes action with ECC private key",
            new EccPrivateKeyUsageContext(pemBytes),
            (context) =>
            {
                bool isEccPrivateKey = false;
                ISignature? signature = null;
                context.UseKey(privateKey =>
                {
                    isEccPrivateKey = privateKey is EccPrivateKey;
                    signature = privateKey.Sign(testData);
                });
                ISignatureVerification verification = publicKey.Verify(signature!);
                return new object[] { isEccPrivateKey, verification.Success };
            })
        .TheTest
        .ShouldPass(because =>
        {
            object[] results = (object[])because.Result;
            bool isEccKey = (bool)results[0];
            bool verified = (bool)results[1];
            because.ItsTrue("key is EccPrivateKey", isEccKey);
            because.ItsTrue("signature verified", verified);
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
            because.ItsTrue("using disposed context throws or fails", (bool)because.Result);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

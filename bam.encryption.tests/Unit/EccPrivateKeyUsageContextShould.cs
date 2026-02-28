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
        string testData = 64.RandomLetters();
        bool isEccPrivateKey = false;

        After.Setup(reg =>
        {
            EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            reg.Set(keyPair.GetEccPublicKey());
            reg.Set(new EccPrivateKeyUsageContext(GetEccPemBytes(keyPair)));
        })
        .When<EccPrivateKeyUsageContext>("executes action with ECC private key", (context, reg) =>
        {
            ISignature? signature = null;
            context.UseKey(privateKey =>
            {
                isEccPrivateKey = privateKey is EccPrivateKey;
                signature = privateKey.Sign(testData);
            });
            return reg.Get<EccPublicKey>().Verify(signature!);
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
        string testData = 64.RandomLetters();

        After.Setup(reg =>
        {
            EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            reg.Set(keyPair.GetEccPublicKey());
            reg.Set(new EccPrivateKeyUsageContext(GetEccPemBytes(keyPair)));
        })
        .When<EccPrivateKeyUsageContext>("signs string with protected key and verifies", (context, reg) =>
        {
            ISignature signature = context.SignWithKey(testData);
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
    public void SignWithKeyBytesReturnsValidSignature()
    {
        byte[] testBytes = System.Text.Encoding.UTF8.GetBytes(64.RandomLetters());

        After.Setup(reg =>
        {
            EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            reg.Set(keyPair.GetEccPublicKey());
            reg.Set(new EccPrivateKeyUsageContext(GetEccPemBytes(keyPair)));
        })
        .When<EccPrivateKeyUsageContext>("signs bytes with protected key and verifies", (context, reg) =>
        {
            ISignature signature = context.SignWithKey(testBytes);
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

    [UnitTest]
    public void DisposesClearsCipherBytes()
    {
        After.Setup(reg =>
        {
            EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair();
            reg.Set(new EccPrivateKeyUsageContext(GetEccPemBytes(keyPair)));
        })
        .When<EccPrivateKeyUsageContext>("clears cipher bytes on dispose", (context, reg) =>
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

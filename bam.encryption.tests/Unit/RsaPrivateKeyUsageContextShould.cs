using Bam.Test;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("RsaPrivateKeyUsageContextShould", Selector = "rpkucs")]
public class RsaPrivateKeyUsageContextShould : UnitTestMenuContainer
{
    [UnitTest]
    public void SignWithKeyStringReturnsValidSignature()
    {
        string testData = 64.RandomLetters();

        After.Setup(reg =>
        {
            RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
            reg.Set(keyPair.GetRsaPublicKey());
            reg.Set(new RsaPrivateKeyUsageContext((byte[])keyPair.Pem.Clone()));
        })
        .When<RsaPrivateKeyUsageContext>("signs string with protected key and verifies", (context, reg) =>
        {
            ISignature signature = context.SignWithKey(testData);
            return reg.Get<RsaPublicKey>().Verify(signature);
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
            RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
            reg.Set(keyPair.GetRsaPublicKey());
            reg.Set(new RsaPrivateKeyUsageContext((byte[])keyPair.Pem.Clone()));
        })
        .When<RsaPrivateKeyUsageContext>("signs bytes with protected key and verifies", (context, reg) =>
        {
            ISignature signature = context.SignWithKey(testBytes);
            return reg.Get<RsaPublicKey>().Verify(signature);
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
    public void UseKeyDecryptsAndExecutesAction()
    {
        string plaintext = "test for use key decrypt";

        After.Setup(reg =>
        {
            RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
            RsaPublicKey publicKey = keyPair.GetRsaPublicKey();
            reg.Set(publicKey);
            reg.Set(publicKey.Encrypt(plaintext));
            reg.Set(new RsaPrivateKeyUsageContext((byte[])keyPair.Pem.Clone()));
        })
        .When<RsaPrivateKeyUsageContext>("decrypts and executes action with key", (context, reg) =>
        {
            string encrypted = reg.Get<string>();
            string? decrypted = null;
            context.UseKey(privateKey =>
            {
                decrypted = ((RsaPrivateKey)privateKey).Decrypt(encrypted);
            });
            return decrypted!;
        })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("decrypted matches original", plaintext.Equals(because.ResultAs<string>()));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

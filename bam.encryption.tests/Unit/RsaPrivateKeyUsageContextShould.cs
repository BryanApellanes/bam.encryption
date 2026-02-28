using Bam.Test;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("RsaPrivateKeyUsageContextShould", Selector = "rpkucs")]
public class RsaPrivateKeyUsageContextShould : UnitTestMenuContainer
{
    [UnitTest]
    public void SignWithKeyStringReturnsValidSignature()
    {
        using RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
        RsaPublicKey publicKey = keyPair.GetRsaPublicKey();
        string testData = 64.RandomLetters();

        When.A<RsaPrivateKeyUsageContext>("signs string with protected key and verifies",
            () => new RsaPrivateKeyUsageContext((byte[])keyPair.Pem.Clone()),
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
        using RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
        RsaPublicKey publicKey = keyPair.GetRsaPublicKey();
        byte[] testBytes = System.Text.Encoding.UTF8.GetBytes(64.RandomLetters());

        When.A<RsaPrivateKeyUsageContext>("signs bytes with protected key and verifies",
            () => new RsaPrivateKeyUsageContext((byte[])keyPair.Pem.Clone()),
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
    public void UseKeyDecryptsAndExecutesAction()
    {
        using RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
        RsaPublicKey publicKey = keyPair.GetRsaPublicKey();
        string plaintext = "test for use key decrypt";
        string encrypted = publicKey.Encrypt(plaintext);

        When.A<RsaPrivateKeyUsageContext>("decrypts and executes action with key",
            () => new RsaPrivateKeyUsageContext((byte[])keyPair.Pem.Clone()),
            (context) =>
            {
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
            because.ItsTrue("decrypted matches original", plaintext.Equals((string)because.Result));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

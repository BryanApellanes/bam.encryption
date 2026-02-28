using Bam.Test;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("RsaPrivateKeyShould", Selector = "rpks")]
public class RsaPrivateKeyShould : UnitTestMenuContainer
{
    [UnitTest]
    public void SignAndVerifyRoundTrip()
    {
        using RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
        RsaPrivateKey privateKey = new RsaPrivateKey(keyPair);
        RsaPublicKey publicKey = keyPair.GetRsaPublicKey();
        string testData = 64.RandomLetters();

        When.A<RsaPrivateKey>("signs string and verifies with public key",
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
        using RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
        RsaPrivateKey privateKey = new RsaPrivateKey(keyPair);
        RsaPublicKey publicKey = keyPair.GetRsaPublicKey();
        byte[] testBytes = System.Text.Encoding.UTF8.GetBytes(64.RandomLetters());

        When.A<RsaPrivateKey>("signs bytes and verifies with public key",
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

    [UnitTest]
    public void DecryptStringEncryptedWithPublicKey()
    {
        using RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
        RsaPrivateKey privateKey = new RsaPrivateKey(keyPair);
        RsaPublicKey publicKey = keyPair.GetRsaPublicKey();
        string plaintext = "test message for encryption";

        When.A<RsaPrivateKey>("decrypts string encrypted with public key",
            privateKey,
            (pk) =>
            {
                string encrypted = publicKey.Encrypt(plaintext);
                return pk.Decrypt(encrypted);
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("decrypted matches original", plaintext.Equals(because.ResultAs<string>()));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void DecryptBytesEncryptedWithPublicKey()
    {
        using RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
        RsaPrivateKey privateKey = new RsaPrivateKey(keyPair);
        RsaPublicKey publicKey = keyPair.GetRsaPublicKey();
        byte[] plainBytes = System.Text.Encoding.UTF8.GetBytes("test bytes for encryption");

        When.A<RsaPrivateKey>("decrypts bytes encrypted with public key",
            privateKey,
            (pk) =>
            {
                byte[] encrypted = publicKey.EncryptBytes(plainBytes);
                return pk.Decrypt(encrypted);
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("decrypted bytes match original", plainBytes.SequenceEqual(because.ResultAs<byte[]>()));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

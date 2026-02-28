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
        using RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
        RsaPrivateKey privateKey = new RsaPrivateKey(keyPair);
        RsaPublicKey publicKey = keyPair.GetRsaPublicKey();
        byte[] testBytes = System.Text.Encoding.UTF8.GetBytes(64.RandomLetters());

        When.A<RsaPrivateKey>("signs bytes and verifies with public key",
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
                string decrypted = pk.Decrypt(encrypted);
                return decrypted;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("decrypted matches original", plaintext.Equals((string)because.Result));
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
                byte[] decrypted = pk.Decrypt(encrypted);
                return new object[] { plainBytes, decrypted };
            })
        .TheTest
        .ShouldPass(because =>
        {
            object[] results = (object[])because.Result;
            byte[] original = (byte[])results[0];
            byte[] decrypted = (byte[])results[1];
            because.ItsTrue("decrypted bytes match original", original.SequenceEqual(decrypted));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

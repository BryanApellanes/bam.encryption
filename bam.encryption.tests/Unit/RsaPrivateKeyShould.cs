using Bam.Test;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("RsaPrivateKeyShould", Selector = "rpks")]
public class RsaPrivateKeyShould : UnitTestMenuContainer
{
    [UnitTest]
    public void SignAndVerifyRoundTrip()
    {
        string testData = 64.RandomLetters();

        After.Setup(reg =>
        {
            RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
            reg.Set(new RsaPrivateKey(keyPair));
            reg.Set(keyPair.GetRsaPublicKey());
        })
        .When<RsaPrivateKey>("signs string and verifies with public key", (pk, reg) =>
        {
            ISignature signature = pk.Sign(testData);
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
    public void SignBytesAndVerifyRoundTrip()
    {
        byte[] testBytes = System.Text.Encoding.UTF8.GetBytes(64.RandomLetters());

        After.Setup(reg =>
        {
            RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
            reg.Set(new RsaPrivateKey(keyPair));
            reg.Set(keyPair.GetRsaPublicKey());
        })
        .When<RsaPrivateKey>("signs bytes and verifies with public key", (pk, reg) =>
        {
            ISignature signature = pk.Sign(testBytes);
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
    public void DecryptStringEncryptedWithPublicKey()
    {
        string plaintext = "test message for encryption";

        After.Setup(reg =>
        {
            RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
            reg.Set(new RsaPrivateKey(keyPair));
            reg.Set(keyPair.GetRsaPublicKey());
        })
        .When<RsaPrivateKey>("decrypts string encrypted with public key", (pk, reg) =>
        {
            string encrypted = reg.Get<RsaPublicKey>().Encrypt(plaintext);
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
        byte[] plainBytes = System.Text.Encoding.UTF8.GetBytes("test bytes for encryption");

        After.Setup(reg =>
        {
            RsaPublicPrivateKeyPair keyPair = new RsaPublicPrivateKeyPair();
            reg.Set(new RsaPrivateKey(keyPair));
            reg.Set(keyPair.GetRsaPublicKey());
        })
        .When<RsaPrivateKey>("decrypts bytes encrypted with public key", (pk, reg) =>
        {
            byte[] encrypted = reg.Get<RsaPublicKey>().EncryptBytes(plainBytes);
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

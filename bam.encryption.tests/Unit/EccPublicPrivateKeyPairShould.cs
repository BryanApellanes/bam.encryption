using Bam.Console;
using Bam.Test;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("EccPublicPrivateKeyPairShould Should", Selector = "eppkps")]
public class EccPublicPrivateKeyPairShould : UnitTestMenuContainer
{

    [UnitTest]
    public void GenerateSameAesKey()
    {
        EccPublicPrivateKeyPair ecc1 = new EccPublicPrivateKeyPair();
        EccPublicPrivateKeyPair ecc2 = new EccPublicPrivateKeyPair();
        string testValue = 128.RandomLetters();

        string decrypted1 = string.Empty;
        string decrypted2 = string.Empty;

        When.A<EccPublicPrivateKeyPair>("generates same AES key from shared secret",
            ecc1,
            (ecc) =>
            {
                AesKey aes1 = ecc1.GetSharedAesKey(ecc2.PublicKeyPem);
                AesKey aes2 = ecc2.GetSharedAesKey(ecc1.PublicKeyPem);

                string cipher1 = aes1.Encrypt(testValue);
                string cipher2 = aes2.Encrypt(testValue);

                decrypted1 = aes1.Decrypt(cipher2);
                decrypted2 = aes2.Decrypt(cipher1);

                return decrypted1;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ResultAs<string>();
            because.ItsTrue("decrypted1 equals original", testValue.Equals(decrypted1));
            because.ItsTrue("decrypted2 equals original", testValue.Equals(decrypted2));
            because.ItsTrue("both decrypted values are equal", decrypted1.Equals(decrypted2));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void GenerateSameAesKeyWithOneEccPair()
    {
        EccPublicPrivateKeyPair ecc = new EccPublicPrivateKeyPair();
        string testValue = 128.RandomLetters();

        string decrypted1 = string.Empty;
        string decrypted2 = string.Empty;

        When.A<EccPublicPrivateKeyPair>("generates same AES key with one ECC pair",
            ecc,
            (e) =>
            {
                AesKey aes1 = e.GetSharedAesKey(e.PublicKeyPem);
                AesKey aes2 = e.GetSharedAesKey(e.PublicKeyPem);

                string cipher1 = aes1.Encrypt(testValue);
                string cipher2 = aes2.Encrypt(testValue);

                decrypted1 = aes1.Decrypt(cipher2);
                decrypted2 = aes2.Decrypt(cipher1);

                return decrypted1;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ResultAs<string>();
            because.ItsTrue("decrypted1 equals original", testValue.Equals(decrypted1));
            because.ItsTrue("decrypted2 equals original", testValue.Equals(decrypted2));
            because.ItsTrue("both decrypted values are equal", decrypted1.Equals(decrypted2));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

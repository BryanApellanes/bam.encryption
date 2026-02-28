using System.Text;
using Bam.Console;
using Bam.Test;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("SymmetricDataEncryptor Should", Selector = "sdes")]
public class SymmetricDataEncryptorShould : UnitTestMenuContainer
{
    [UnitTest]
    public void EncryptAndDecryptText()
    {
        string text = 1000.SecureAlphaNumericCharacters();

        When.A<SymmetricDataEncryptor<object>>("encrypts and decrypts text",
            () => new SymmetricDataEncryptor<object>(new AesKey()),
            (encryptor) =>
            {
                string base64Cipher = encryptor.Encrypt(text);
                IDecryptor decryptor = encryptor.GetDecryptor();
                string decrypted = decryptor.Decrypt(base64Cipher);
                return decrypted;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("decrypted text equals original", text.Equals(because.ResultAs<string>()));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void EncryptAndDecryptBytes()
    {
        string text = 1000.SecureAlphaNumericCharacters();
        byte[] bytes = Encoding.UTF8.GetBytes(text);

        When.A<SymmetricDataEncryptor<object>>("encrypts and decrypts bytes",
            () => new SymmetricDataEncryptor<object>(new AesKey()),
            (encryptor) =>
            {
                byte[] cipherBytes = encryptor.Encrypt(bytes);
                IDecryptor decryptor = encryptor.GetDecryptor();
                byte[] decryptedBytes = decryptor.Decrypt(cipherBytes);
                string decrypted = Encoding.UTF8.GetString(decryptedBytes);
                return decrypted;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("decrypted bytes equal original text", text.Equals(because.ResultAs<string>()));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

using System.Text;
using Bam.Console;
using Bam.Test;

namespace Bam.Encryption.Tests.Unit;
    
[UnitTestMenu("SymmetricDataEncryptor Should", Selector = "sdes")]
public class SymmetricDataEncryptorShould : UnitTestMenuContainer
{
    [UnitTest]
    public async Task EncryptAndDecryptText()
    {
        string text = 1000.SecureAlphaNumericCharacters();
        IEncryptor encryptor = new SymmetricDataEncryptor<object>(new AesKey());
        string base64Cipher = encryptor.Encrypt(text);
        IDecryptor decryptor = encryptor.GetDecryptor();
        
        string decrypted = decryptor.Decrypt(base64Cipher);
        
        decrypted.ShouldEqual(text);
        Message.PrintLine(decrypted);
    }
    
    [UnitTest]
    public async Task EncryptAndDecryptBytes()
    {
        string text = 1000.SecureAlphaNumericCharacters();
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        
        IEncryptor encryptor = new SymmetricDataEncryptor<object>(new AesKey());
        byte[] base64Cipher = encryptor.Encrypt(bytes); 
        IDecryptor decryptor = encryptor.GetDecryptor();
        
        byte[] decryptedBytes = decryptor.Decrypt(base64Cipher);
        string decrypted = Encoding.UTF8.GetString(decryptedBytes);
        decrypted.ShouldEqual(text);
        Message.PrintLine(decrypted);
    }
}
using System.Text;
using System.Web;
using Bam.Console;
using Bam.Test;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Bam.Encryption.Tests.Unit;

[UnitTestMenu("EccPublicPrivateKeyPairShould Should", Selector = "eppkps")]
public class EccPublicPrivateKeyPairShould : UnitTestMenuContainer
{
    
    [UnitTest]
    public void GenerateSameAesKey()
    {
        EccPublicPrivateKeyPair ecc1 = new EccPublicPrivateKeyPair();
        EccPublicPrivateKeyPair ecc2 = new EccPublicPrivateKeyPair();

        AesKey aes1 = ecc1.GetSharedAesKey(ecc2.PublicKeyPem);
        AesKey aes2 = ecc2.GetSharedAesKey(ecc1.PublicKeyPem);

        string testValue = 128.RandomLetters();
        
        string cipher1 = aes1.Encrypt(testValue);
        string cipher2 = aes2.Encrypt(testValue);
        
        string decrypted1 = aes1.Decrypt(cipher2);
        string decrypted2 = aes2.Decrypt(cipher1);
        
        decrypted1.ShouldBeEqualTo(testValue);
        decrypted2.ShouldBeEqualTo(testValue);
        
        decrypted1.ShouldBeEqualTo(decrypted2);
    }
}
using System.Text;
using System.Web;
using Bam.Console;
using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Encryption.Tests.TestClasses;
using Bam.Test;
using Bam;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Engines;

namespace Bam.ServiceProxy.Encryption.Tests.Unit;

[UnitTestMenu("EncryptionTransformers Should", Selector = "sgs")]
public class EncryptionTransformersShould : UnitTestMenuContainer
{
    [UnitTest]
    public void AesKeyVectorPairTest() 
    {
        AesKey aesKey = new AesKey();
        string testData = "this is the test data";
        string cipher = aesKey.Encrypt(testData);
        string deciphered = aesKey.Decrypt(cipher);

        deciphered.ShouldBeEqualTo(testData);
    }

    [UnitTest]
    public void TransformAes()
    {
        AesKey aesKey = new AesKey();
        AesByteTransformer aesByteTransformer = new AesByteTransformer(aesKey);

        string testData = "this is the test data";
        byte[] testDataBytes = Encoding.UTF8.GetBytes(testData);

        byte[] cipherData = aesByteTransformer.Transform(testDataBytes);

        byte[] deciphered = aesByteTransformer.GetReverseTransformer().ReverseTransform(cipherData);

        Expect.AreEqual(testDataBytes, deciphered);
        string decipheredTestData = Encoding.UTF8.GetString(deciphered);
        Expect.AreEqual(testData, decipheredTestData);
    }

    [UnitTest]
    public void TransformAesBase64()
    {
        AesKey aesKey = new AesKey();
        AesBase64Transformer aesBase64Transformer = new AesBase64Transformer(aesKey);

        string testData = "this is the test data";
        string base64Cipher = aesBase64Transformer.Transform(testData);

        Expect.IsFalse(testData.Equals(base64Cipher));

        string decipherd = aesBase64Transformer.GetReverseTransformer().ReverseTransform(base64Cipher);

        Equals(testData, decipherd);
    }
    
    [UnitTest]
    public void SymmetricEncryptorEncryptAndDecryptDataTest() 
    {
        AesKey aesKey = new AesKey();
        SymmetricDataEncryptor<TestMonkey> encryptor = new SymmetricDataEncryptor<TestMonkey>(aesKey);

        TestMonkey monkey = new TestMonkey()
        {
            Name = Guid.NewGuid().ToString(),
            TailCount = 1
        };

        IDecryptor<TestMonkey> decryptor = encryptor.GetDecryptor();
        Cipher<TestMonkey> cipher = encryptor.Encrypt(monkey);
        TestMonkey deciphered = decryptor.DecryptCipher(cipher);
            
        Expect.AreEqual(monkey.Name, deciphered.Name);
        Expect.AreEqual(monkey.TailCount, deciphered.TailCount);
    }


    
    [UnitTest]
    public void TransformRsaBytes()
    {
        RsaPublicPrivateKeyPair rsaKey = new RsaPublicPrivateKeyPair();
        RsaByteTransformer rsaByteTransformer = new RsaByteTransformer(rsaKey);

        string testData = "this is the test data";
        byte[] testDataBytes = Encoding.UTF8.GetBytes(testData);
        byte[] cipher = rsaByteTransformer.Transform(testDataBytes);

        Expect.IsFalse(testDataBytes.Length == cipher.Length);

        string base64Data = Convert.ToBase64String(testDataBytes);
        string base64Cipher = Convert.ToBase64String(cipher);

        Expect.IsNotNullOrEmpty(base64Data);
        Expect.IsNotNullOrEmpty(base64Cipher);
        Expect.IsFalse(base64Data.Equals(base64Cipher));

        byte[] deciphered = rsaByteTransformer.GetReverseTransformer().ReverseTransform(cipher);
        string decipheredText = Encoding.UTF8.GetString(deciphered);

        Expect.AreEqual(testData, decipheredText);
    }

    [UnitTest]
    public void TransformRsaBase64()
    {
        RsaPublicPrivateKeyPair rsaKey = new RsaPublicPrivateKeyPair();
        RsaBase64Transformer rsaBase64Transformer = new RsaBase64Transformer(rsaKey);

        string testData = "this is the test data";
        string base64Cipher = rsaBase64Transformer.Transform(testData);

        Expect.IsFalse(testData.Length == base64Cipher.Length);
        Expect.IsNotNullOrEmpty(base64Cipher);
        Expect.IsFalse(testData.Equals(base64Cipher));

        string deciphered = rsaBase64Transformer.GetReverseTransformer().ReverseTransform(base64Cipher);

        Expect.AreEqual(testData, deciphered);
    }

    
    [UnitTest]
    public void SymmetricEncryptorEncryptAndDecryptStringTest()  
    {
        AesKey aesKey = new AesKey();
        SymmetricDataEncryptor<TestMonkey> encryptor = new SymmetricDataEncryptor<TestMonkey>(aesKey);

        string testValue = $"this is the test value {Guid.NewGuid()}";
        string cipherString = encryptor.Encrypt(testValue);            

        IDecryptor decryptor = encryptor.GetDecryptor();
            
        string decipheredString = decryptor.Decrypt(cipherString);
        Expect.AreEqual(testValue, decipheredString);
    }

    [UnitTest]
    public void SymmetricEncryptorEncryptAndDecryptBytesTest() 
    {
        AesKey aesKey = new AesKey();
        SymmetricDataEncryptor<TestMonkey> encryptor = new SymmetricDataEncryptor<TestMonkey>(aesKey);

        string testValue = $"this is the test value {Guid.NewGuid()}";
        byte[] utf8 = Encoding.UTF8.GetBytes(testValue);

        IDecryptor decryptor = encryptor.GetDecryptor();
            
        byte[] cipherBytes = encryptor.Encrypt(utf8);
        byte[] decipheredBytes = decryptor.Decrypt(cipherBytes);
        string deciphered = Encoding.UTF8.GetString(decipheredBytes);
        Expect.AreEqual(testValue, deciphered);
    }

        [UnitTest]
        public void AsymmetricEncryptorEncryptAndDecryptStringTest()
        {
            RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair = new RsaPublicPrivateKeyPair();
            RsaAsymmetricDataEncryptor<TestMonkey> encryptor = new RsaAsymmetricDataEncryptor<TestMonkey>(rsaPublicPrivateKeyPair);

            string testValue = $"this is the test value {Guid.NewGuid()}";
            string cipherString = encryptor.Encrypt(testValue);

            IDecryptor decryptor = encryptor.GetDecryptor();

            string decipheredString = decryptor.Decrypt(cipherString);
            Expect.AreEqual(testValue, decipheredString);
        }

        [UnitTest]
        public void AsymmetricEncryptorEncryptAndDecryptBytesTest()
        {
            RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair = new RsaPublicPrivateKeyPair();
            RsaAsymmetricDataEncryptor<TestMonkey> encryptor = new RsaAsymmetricDataEncryptor<TestMonkey>(rsaPublicPrivateKeyPair);

            string testValue = $"this is the test value {Guid.NewGuid()}";
            byte[] utf8 = Encoding.UTF8.GetBytes(testValue);

            IDecryptor decryptor = encryptor.GetDecryptor();

            byte[] cipherBytes = encryptor.Encrypt(utf8);
            byte[] decipheredBytes = decryptor.Decrypt(cipherBytes);
            string deciphered = Encoding.UTF8.GetString(decipheredBytes);
            Expect.AreEqual(testValue, deciphered);
        }

        [UnitTest]
        public void ValueTransformerPipelineFactoryTest()
        {
            ServiceRegistry testRegistry = new ServiceRegistry();
            testRegistry.For<IAesKeySource>().Use<AesKey>();

            ValueTransformerPipelineFactory factory = new ValueTransformerPipelineFactory(testRegistry);
            ValueTransformerPipeline<TestMonkey> valueTransformerPipeline = factory.Create<TestMonkey>( typeof(AesByteTransformer).Assembly,"aes");

            string testName = "test_".RandomLetters(8);
            TestMonkey testMonkey = new TestMonkey
            {
                Name = testName,
                TailCount = RandomNumber.Between(1, 9),
            };

            string cipher = valueTransformerPipeline.Transform(testMonkey).ToBase64();

            TestMonkey deciphered = valueTransformerPipeline.GetReverseTransformer().ReverseTransform(cipher.FromBase64());

            Expect.AreEqual(testMonkey.Name, testName);
            Expect.AreEqual(deciphered.Name, testName);
            Expect.AreEqual(deciphered.TailCount, testMonkey.TailCount);
            Expect.IsGreaterThan(deciphered.TailCount, 0);
        }
}
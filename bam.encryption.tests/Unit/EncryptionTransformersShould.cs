using System.Text;
using Bam.Console;
using Bam.DependencyInjection;
using Bam.Encryption;
using Bam.Encryption.Tests.TestClasses;
using Bam.Test;

namespace Bam.ServiceProxy.Encryption.Tests.Unit;

[UnitTestMenu("EncryptionTransformers Should", Selector = "sgs")]
public class EncryptionTransformersShould : UnitTestMenuContainer
{
    [UnitTest]
    public void AesKeyVectorPairTest()
    {
        string testData = "this is the test data";

        When.A<AesKey>("encrypts and decrypts with AES key",
            (aesKey) =>
            {
                string cipher = aesKey.Encrypt(testData);
                string deciphered = aesKey.Decrypt(cipher);
                return deciphered;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("deciphered equals original", testData.Equals((string)because.Result));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void TransformAes()
    {
        string testData = "this is the test data";
        byte[] testDataBytes = Encoding.UTF8.GetBytes(testData);

        When.A<AesByteTransformer>("round-trips bytes through AES byte transformer",
            () => new AesByteTransformer(new AesKey()),
            (aesByteTransformer) =>
            {
                byte[] cipherData = aesByteTransformer.Transform(testDataBytes);
                byte[] deciphered = aesByteTransformer.GetReverseTransformer().ReverseTransform(cipherData);
                string decipheredText = Encoding.UTF8.GetString(deciphered);
                return new object[] { testDataBytes, deciphered, decipheredText };
            })
        .TheTest
        .ShouldPass(because =>
        {
            object[] results = (object[])because.Result;
            byte[] original = (byte[])results[0];
            byte[] deciphered = (byte[])results[1];
            string decipheredText = (string)results[2];
            because.ItsTrue("byte arrays match", original.SequenceEqual(deciphered));
            because.ItsTrue("deciphered text equals original", testData.Equals(decipheredText));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void TransformAesBase64()
    {
        string testData = "this is the test data";

        When.A<AesBase64Transformer>("round-trips string through AES base64 transformer",
            () => new AesBase64Transformer(new AesKey()),
            (aesBase64Transformer) =>
            {
                string base64Cipher = aesBase64Transformer.Transform(testData);
                string deciphered = aesBase64Transformer.GetReverseTransformer().ReverseTransform(base64Cipher);
                return new object[] { base64Cipher, deciphered };
            })
        .TheTest
        .ShouldPass(because =>
        {
            object[] results = (object[])because.Result;
            string base64Cipher = (string)results[0];
            string deciphered = (string)results[1];
            because.ItsTrue("cipher differs from original", !testData.Equals(base64Cipher));
            because.ItsTrue("deciphered equals original", testData.Equals(deciphered));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SymmetricEncryptorEncryptAndDecryptDataTest()
    {
        TestMonkey monkey = new TestMonkey()
        {
            Name = Guid.NewGuid().ToString(),
            TailCount = 1
        };

        When.A<SymmetricDataEncryptor<TestMonkey>>("encrypts and decrypts data object",
            () => new SymmetricDataEncryptor<TestMonkey>(new AesKey()),
            (encryptor) =>
            {
                IDecryptor<TestMonkey> decryptor = encryptor.GetDecryptor();
                Cipher<TestMonkey> cipher = encryptor.Encrypt(monkey);
                TestMonkey deciphered = decryptor.DecryptCipher(cipher);
                return deciphered;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult.IsNotNull()
                .As<TestMonkey>("Name equals original", m => monkey.Name.Equals(m?.Name))
                .As<TestMonkey>("TailCount equals original", m => monkey.TailCount == m?.TailCount);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void TransformRsaBytes()
    {
        string testData = "this is the test data";
        byte[] testDataBytes = Encoding.UTF8.GetBytes(testData);

        When.A<RsaByteTransformer>("round-trips bytes through RSA byte transformer",
            () => new RsaByteTransformer(new RsaPublicPrivateKeyPair()),
            (rsaByteTransformer) =>
            {
                byte[] cipher = rsaByteTransformer.Transform(testDataBytes);
                byte[] deciphered = rsaByteTransformer.GetReverseTransformer().ReverseTransform(cipher);
                string decipheredText = Encoding.UTF8.GetString(deciphered);

                string base64Data = Convert.ToBase64String(testDataBytes);
                string base64Cipher = Convert.ToBase64String(cipher);

                return new object[] { cipher, deciphered, decipheredText, base64Data, base64Cipher };
            })
        .TheTest
        .ShouldPass(because =>
        {
            object[] results = (object[])because.Result;
            byte[] cipher = (byte[])results[0];
            byte[] deciphered = (byte[])results[1];
            string decipheredText = (string)results[2];
            string base64Data = (string)results[3];
            string base64Cipher = (string)results[4];
            because.ItsTrue("cipher length differs from original", testDataBytes.Length != cipher.Length);
            because.ItsTrue("base64 data is not empty", !string.IsNullOrEmpty(base64Data));
            because.ItsTrue("base64 cipher is not empty", !string.IsNullOrEmpty(base64Cipher));
            because.ItsTrue("base64 cipher differs from base64 data", !base64Data.Equals(base64Cipher));
            because.ItsTrue("deciphered text equals original", testData.Equals(decipheredText));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void TransformRsaBase64()
    {
        string testData = "this is the test data";

        When.A<RsaBase64Transformer>("round-trips string through RSA base64 transformer",
            () => new RsaBase64Transformer(new RsaPublicPrivateKeyPair()),
            (rsaBase64Transformer) =>
            {
                string base64Cipher = rsaBase64Transformer.Transform(testData);
                string deciphered = rsaBase64Transformer.GetReverseTransformer().ReverseTransform(base64Cipher);
                return new object[] { base64Cipher, deciphered };
            })
        .TheTest
        .ShouldPass(because =>
        {
            object[] results = (object[])because.Result;
            string base64Cipher = (string)results[0];
            string deciphered = (string)results[1];
            because.ItsTrue("cipher length differs from original", testData.Length != base64Cipher.Length);
            because.ItsTrue("cipher is not empty", !string.IsNullOrEmpty(base64Cipher));
            because.ItsTrue("cipher differs from original", !testData.Equals(base64Cipher));
            because.ItsTrue("deciphered equals original", testData.Equals(deciphered));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SymmetricEncryptorEncryptAndDecryptStringTest()
    {
        string testValue = $"this is the test value {Guid.NewGuid()}";

        When.A<SymmetricDataEncryptor<TestMonkey>>("encrypts and decrypts string symmetrically",
            () => new SymmetricDataEncryptor<TestMonkey>(new AesKey()),
            (encryptor) =>
            {
                string cipherString = encryptor.Encrypt(testValue);
                IDecryptor decryptor = encryptor.GetDecryptor();
                string decipheredString = decryptor.Decrypt(cipherString);
                return decipheredString;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("deciphered string equals original", testValue.Equals((string)because.Result));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SymmetricEncryptorEncryptAndDecryptBytesTest()
    {
        string testValue = $"this is the test value {Guid.NewGuid()}";
        byte[] utf8 = Encoding.UTF8.GetBytes(testValue);

        When.A<SymmetricDataEncryptor<TestMonkey>>("encrypts and decrypts bytes symmetrically",
            () => new SymmetricDataEncryptor<TestMonkey>(new AesKey()),
            (encryptor) =>
            {
                IDecryptor decryptor = encryptor.GetDecryptor();
                byte[] cipherBytes = encryptor.Encrypt(utf8);
                byte[] decipheredBytes = decryptor.Decrypt(cipherBytes);
                string deciphered = Encoding.UTF8.GetString(decipheredBytes);
                return deciphered;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("deciphered equals original", testValue.Equals((string)because.Result));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AsymmetricEncryptorEncryptAndDecryptStringTest()
    {
        string testValue = $"this is the test value {Guid.NewGuid()}";

        When.A<RsaAsymmetricDataEncryptor<TestMonkey>>("encrypts and decrypts string asymmetrically",
            () => new RsaAsymmetricDataEncryptor<TestMonkey>(new RsaPublicPrivateKeyPair()),
            (encryptor) =>
            {
                string cipherString = encryptor.Encrypt(testValue);
                IDecryptor decryptor = encryptor.GetDecryptor();
                string decipheredString = decryptor.Decrypt(cipherString);
                return decipheredString;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("deciphered string equals original", testValue.Equals((string)because.Result));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AsymmetricEncryptorEncryptAndDecryptBytesTest()
    {
        string testValue = $"this is the test value {Guid.NewGuid()}";
        byte[] utf8 = Encoding.UTF8.GetBytes(testValue);

        When.A<RsaAsymmetricDataEncryptor<TestMonkey>>("encrypts and decrypts bytes asymmetrically",
            () => new RsaAsymmetricDataEncryptor<TestMonkey>(new RsaPublicPrivateKeyPair()),
            (encryptor) =>
            {
                IDecryptor decryptor = encryptor.GetDecryptor();
                byte[] cipherBytes = encryptor.Encrypt(utf8);
                byte[] decipheredBytes = decryptor.Decrypt(cipherBytes);
                string deciphered = Encoding.UTF8.GetString(decipheredBytes);
                return deciphered;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.ItsTrue("deciphered equals original", testValue.Equals((string)because.Result));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void ValueTransformerPipelineFactoryTest()
    {
        string testName = "test_".RandomLetters(8);
        TestMonkey testMonkey = new TestMonkey
        {
            Name = testName,
            TailCount = RandomNumber.Between(1, 9),
        };

        When.A<ValueTransformerPipelineFactory>("creates and uses a value transformer pipeline",
            () =>
            {
                ServiceRegistry testRegistry = new ServiceRegistry();
                testRegistry.For<IAesKeySource>().Use<AesKey>();
                return new ValueTransformerPipelineFactory(testRegistry);
            },
            (factory) =>
            {
                ValueTransformerPipeline<TestMonkey> pipeline = factory.Create<TestMonkey>(typeof(AesByteTransformer).Assembly, "aes");
                string cipher = pipeline.Transform(testMonkey).ToBase64();
                TestMonkey deciphered = pipeline.GetReverseTransformer().ReverseTransform(cipher.FromBase64());
                return deciphered;
            })
        .TheTest
        .ShouldPass(because =>
        {
            because.TheResult.IsNotNull()
                .As<TestMonkey>("Name equals original", m => testName.Equals(m?.Name))
                .As<TestMonkey>("TailCount equals original", m => testMonkey.TailCount == m?.TailCount)
                .As<TestMonkey>("TailCount is greater than 0", m => m?.TailCount > 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }
}

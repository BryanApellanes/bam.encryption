using Bam.Console;
using Bam.Test;
using Bam.Encryption.Tests.TestClasses;

namespace Bam.Encryption.Tests.Unit;

/// <summary>
/// Pins the password-based string encryption after it stopped using the obsolete RijndaelManaged and
/// Rfc2898DeriveBytes constructor (bam.encryption#17): text encrypted before the change must still decrypt.
/// </summary>
[UnitTestMenu("Rijndael Should", Selector = "rs")]
public class RijndaelShould : UnitTestMenuContainer
{
    private const string Password = "correct horse battery staple";
    private const string PlainText = "the quick brown fox jumps over the lazy dog";

    /// <summary>
    /// Produced outside this code base with .NET Framework 4.8 (Windows PowerShell 5.1): RijndaelManaged with its
    /// defaults (256-bit key, CBC, PKCS7), key from <c>new Rfc2898DeriveBytes(Password, salt)</c>, IV bytes 1..16,
    /// in the layout EncryptStringAES writes (IV length, IV, cipher).
    /// </summary>
    private const string LegacyCipher = "EAAAAAECAwQFBgcICQoLDA0ODxAmPanZQ3s1BkE4T2bRPBm77Ujx0n/17DX2K+UqDqyt4m5DS/00nSNRzGDNE14ZV1Q=";

    [UnitTest]
    public void DecryptTextEncryptedByTheLegacyImplementation()
    {
        When.A<string>("decrypts a cipher produced by RijndaelManaged on .NET Framework",
            LegacyCipher,
            (cipher) => Rijndael.DecryptStringAES(cipher, Password))
        .TheTest
        .ShouldPass<string>((because, _, decrypted) =>
        {
            because.ItsTrue("the legacy cipher decrypts to the original text", PlainText.Equals(decrypted));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RoundTripAndUseAFreshIvEachTime()
    {
        When.A<string>("encrypts the same text twice and decrypts both",
            PlainText,
            (text) =>
            {
                string first = Rijndael.EncryptStringAES(text, Password);
                string second = Rijndael.EncryptStringAES(text, Password);
                return new RoundTripOutcome(
                    first,
                    second,
                    Rijndael.DecryptStringAES(first, Password),
                    Rijndael.DecryptStringAES(second, Password),
                    text.AesPasswordEncrypt(Password).AesPasswordDecrypt(Password));
            })
        .TheTest
        .ShouldPass<RoundTripOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("the first cipher decrypts", PlainText.Equals(outcome.FirstDecrypted));
            because.ItsTrue("the second cipher decrypts", PlainText.Equals(outcome.SecondDecrypted));
            because.ItsTrue("each encryption uses its own IV", !outcome.First.Equals(outcome.Second));
            because.ItsTrue("the cipher has the legacy layout and length", Convert.FromBase64String(outcome.First).Length == Convert.FromBase64String(LegacyCipher).Length);
            because.ItsTrue("the password extensions round trip", PlainText.Equals(outcome.ExtensionRoundTrip));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void NotDecryptWithTheWrongPassword()
    {
        When.A<string>("decrypts the legacy cipher with the wrong password",
            LegacyCipher,
            (cipher) =>
            {
                try
                {
                    return !PlainText.Equals(Rijndael.DecryptStringAES(cipher, "not the password"));
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    return true;
                }
            })
        .TheTest
        .ShouldPass<bool>((because, _, rejected) =>
        {
            because.ItsTrue("the wrong password does not yield the text", rejected);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    /// <summary>
    /// The obsolete Rfc2898DeriveBytes constructor encoded the password with Encoding.UTF8, which replaces an
    /// unpaired surrogate with U+FFFD. A password like that must still work, and must derive the same key as the
    /// same password with U+FFFD in place of the surrogate.
    /// </summary>
    [UnitTest]
    public void AcceptAPasswordWithAnUnpairedSurrogate()
    {
        When.A<string>("encrypts with a password that holds an unpaired surrogate",
            "a\uD800b",
            (password) =>
            {
                string cipher = Rijndael.EncryptStringAES(PlainText, password);
                return new LoneSurrogateOutcome(
                    Rijndael.DecryptStringAES(cipher, password),
                    Rijndael.DecryptStringAES(cipher, "a�b"));
            })
        .TheTest
        .ShouldPass<LoneSurrogateOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("the cipher decrypts with the same password", PlainText.Equals(outcome.SamePassword));
            because.ItsTrue("the key matches the replacement-character encoding the old constructor used", PlainText.Equals(outcome.ReplacementPassword));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RoundTripAnObjectThroughEncryptedXml()
    {
        When.A<TestMonkey>("serializes to encrypted xml with a generated key and reads it back",
            new TestMonkey { Name = "George", TailCount = 1 },
            (monkey) =>
            {
                string cipher = monkey.ToBase64EncodedEncryptedXml(out AesKey key);
                TestMonkey back = Aes.Deserialize<TestMonkey>(cipher, key);
                return new XmlOutcome(key.Key.Length, key.IV.Length, back.Name, back.TailCount);
            })
        .TheTest
        .ShouldPass<XmlOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("the generated key is 256 bits", outcome.KeyBytes == 32);
            because.ItsTrue("the generated IV is one block", outcome.IvBytes == 16);
            because.ItsTrue("the object reads back", "George".Equals(outcome.Name) && outcome.TailCount == 1);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RoundTripThroughAnRsaKeyFile()
    {
        When.A<RsaKeyFile>("encrypts and decrypts with a new key file",
            () => new RsaKeyFile(),
            (keyFile) => keyFile.DecryptWithPrivateKey(keyFile.EncryptWithPublicKey(PlainText)))
        .TheTest
        .ShouldPass<string>((because, _, decrypted) =>
        {
            because.ItsTrue("the text survives the round trip", PlainText.Equals(decrypted));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private sealed record RoundTripOutcome(string First, string Second, string FirstDecrypted, string SecondDecrypted, string ExtensionRoundTrip);

    private sealed record LoneSurrogateOutcome(string SamePassword, string ReplacementPassword);

    private sealed record XmlOutcome(int KeyBytes, int IvBytes, string Name, int TailCount);
}

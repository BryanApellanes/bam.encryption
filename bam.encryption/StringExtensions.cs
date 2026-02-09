using Org.BouncyCastle.Security;

namespace Bam.Encryption;

public static class StringExtensions
{
    public static byte[] DoubleHmacSha256(this string str, byte[] key)
    {
        return HmacSha256(HmacSha256(str, key).ToBase64(), key);
    }

    public static byte[] DoubleHmacSha256(this string str, string key)
    {
        return HmacSha256(HmacSha256(str, key).ToBase64(), key);
    }
    
    public static byte[] HmacSha256(this string str, byte[] key)
    {
        return Hmac.Sha256(str, key);
    }

    public static byte[] HmacSha256(this string str, string key)
    {
        return Hmac.Sha256(str, key);
    }
}
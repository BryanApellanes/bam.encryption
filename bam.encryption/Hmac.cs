using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Bam.Encryption;

public static class Hmac
{
    public static byte[] Sha256(string text, string key)
    {
        HMACSHA256 sha256 = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        return sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
    }

    public static byte[] Sha1(string text, string key)
    {
        HMACSHA1 hmac = new HMACSHA1(Encoding.UTF8.GetBytes(key));
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(text));
    }

    public static byte[] DoubleSha256(string text, string key)
    {
        HMACSHA256 firstHmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        byte[] firstResult = firstHmac.ComputeHash(Encoding.UTF8.GetBytes(text));
        HMACSHA256 secondHmac = new HMACSHA256(firstResult);
        return secondHmac.ComputeHash(Encoding.UTF8.GetBytes(text));
    }

    public static byte[] DoubleSha1(string text, string key)
    {
        HMACSHA1 firstHmac = new HMACSHA1(Encoding.UTF8.GetBytes(key));
        byte[] firstResult = firstHmac.ComputeHash(Encoding.UTF8.GetBytes(text));
        HMACSHA1 secondHmac = new HMACSHA1(firstResult);
        return secondHmac.ComputeHash(Encoding.UTF8.GetBytes(text));
    }
}
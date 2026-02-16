using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Bam.Encryption;

/// <summary>
/// Provides static methods for computing HMAC (Hash-based Message Authentication Code) values using SHA-256 and SHA-1 algorithms.
/// </summary>
public static class Hmac
{
    /// <summary>
    /// Computes an HMAC-SHA256 hash of the specified text using the given key bytes.
    /// </summary>
    /// <param name="text">The text to hash.</param>
    /// <param name="key">The HMAC key bytes.</param>
    /// <returns>The HMAC-SHA256 hash as a byte array.</returns>
    public static byte[] Sha256(string text, byte[] key)
    {
        HMACSHA256 sha256 = new HMACSHA256(key);
        return sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>
    /// Computes an HMAC-SHA256 hash of the specified byte array using the given key bytes.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="key">The HMAC key bytes.</param>
    /// <returns>The HMAC-SHA256 hash as a byte array.</returns>
    public static byte[] Sha256(byte[] data, byte[] key)
    {
        HMACSHA256 sha256 = new HMACSHA256(key);
        return sha256.ComputeHash(data);
    }

    /// <summary>
    /// Computes an HMAC-SHA1 hash of the specified byte array using the given key bytes.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="key">The HMAC key bytes.</param>
    /// <returns>The HMAC-SHA1 hash as a byte array.</returns>
    public static byte[] Sha1(byte[] data, byte[] key)
    {
        HMACSHA1 hmac = new HMACSHA1(key);
        return hmac.ComputeHash(data);
    }
    /// <summary>
    /// Computes an HMAC-SHA256 hash of the specified text using the given string key (UTF-8 encoded).
    /// </summary>
    /// <param name="text">The text to hash.</param>
    /// <param name="key">The HMAC key string.</param>
    /// <returns>The HMAC-SHA256 hash as a byte array.</returns>
    public static byte[] Sha256(string text, string key)
    {
        HMACSHA256 sha256 = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        return sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>
    /// Computes an HMAC-SHA1 hash of the specified text using the given string key (UTF-8 encoded).
    /// </summary>
    /// <param name="text">The text to hash.</param>
    /// <param name="key">The HMAC key string.</param>
    /// <returns>The HMAC-SHA1 hash as a byte array.</returns>
    public static byte[] Sha1(string text, string key)
    {
        HMACSHA1 hmac = new HMACSHA1(Encoding.UTF8.GetBytes(key));
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>
    /// Computes a double HMAC-SHA256 hash, using the result of the first HMAC as the key for the second.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="key">The HMAC key bytes for the first hash.</param>
    /// <returns>The double HMAC-SHA256 hash as a byte array.</returns>
    public static byte[] DoubleSha256(byte[] data, byte[] key)
    {
        HMACSHA256 firstHmac = new HMACSHA256(key);
        byte[] firstResult = firstHmac.ComputeHash(data);
        HMACSHA256 secondHmac = new HMACSHA256(firstResult);
        return secondHmac.ComputeHash(data);
    }
    /// <summary>
    /// Computes a double HMAC-SHA256 hash of text, using the result of the first HMAC as the key for the second.
    /// </summary>
    /// <param name="text">The text to hash.</param>
    /// <param name="key">The HMAC key string for the first hash.</param>
    /// <returns>The double HMAC-SHA256 hash as a byte array.</returns>
    public static byte[] DoubleSha256(string text, string key)
    {
        HMACSHA256 firstHmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        byte[] firstResult = firstHmac.ComputeHash(Encoding.UTF8.GetBytes(text));
        HMACSHA256 secondHmac = new HMACSHA256(firstResult);
        return secondHmac.ComputeHash(Encoding.UTF8.GetBytes(text));
    }

    /// <summary>
    /// Computes a double HMAC-SHA1 hash of text, using the result of the first HMAC as the key for the second.
    /// </summary>
    /// <param name="text">The text to hash.</param>
    /// <param name="key">The HMAC key string for the first hash.</param>
    /// <returns>The double HMAC-SHA1 hash as a byte array.</returns>
    public static byte[] DoubleSha1(string text, string key)
    {
        HMACSHA1 firstHmac = new HMACSHA1(Encoding.UTF8.GetBytes(key));
        byte[] firstResult = firstHmac.ComputeHash(Encoding.UTF8.GetBytes(text));
        HMACSHA1 secondHmac = new HMACSHA1(firstResult);
        return secondHmac.ComputeHash(Encoding.UTF8.GetBytes(text));
    }
}
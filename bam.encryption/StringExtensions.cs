using Org.BouncyCastle.Security;

namespace Bam.Encryption;

/// <summary>
/// Provides HMAC-SHA256 extension methods for strings.
/// </summary>
public static class StringExtensions
{
    /// <summary>
    /// Computes a double HMAC-SHA256 hash of the string using the specified byte array key.
    /// </summary>
    /// <param name="str">The string to hash.</param>
    /// <param name="key">The HMAC key as a byte array.</param>
    /// <returns>The double HMAC-SHA256 hash as a byte array.</returns>
    public static byte[] DoubleHmacSha256(this string str, byte[] key)
    {
        return HmacSha256(HmacSha256(str, key).ToBase64(), key);
    }

    /// <summary>
    /// Computes a double HMAC-SHA256 hash of the string using the specified string key.
    /// </summary>
    /// <param name="str">The string to hash.</param>
    /// <param name="key">The HMAC key as a string.</param>
    /// <returns>The double HMAC-SHA256 hash as a byte array.</returns>
    public static byte[] DoubleHmacSha256(this string str, string key)
    {
        return HmacSha256(HmacSha256(str, key).ToBase64(), key);
    }

    /// <summary>
    /// Computes an HMAC-SHA256 hash of the string using the specified byte array key.
    /// </summary>
    /// <param name="str">The string to hash.</param>
    /// <param name="key">The HMAC key as a byte array.</param>
    /// <returns>The HMAC-SHA256 hash as a byte array.</returns>
    public static byte[] HmacSha256(this string str, byte[] key)
    {
        return Hmac.Sha256(str, key);
    }

    /// <summary>
    /// Computes an HMAC-SHA256 hash of the string using the specified string key.
    /// </summary>
    /// <param name="str">The string to hash.</param>
    /// <param name="key">The HMAC key as a string.</param>
    /// <returns>The HMAC-SHA256 hash as a byte array.</returns>
    public static byte[] HmacSha256(this string str, string key)
    {
        return Hmac.Sha256(str, key);
    }
}
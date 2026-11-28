using System.Security.Cryptography;
using System.Text;

namespace Bam.Encryption;

/// <summary>
/// Key derivation for session keys (bam.encryption#38): HKDF-SHA256 (RFC 5869) with a required salt and a required
/// label, so two keys derived from one secret for different purposes never coincide.
/// </summary>
public static class KeyDerivation
{
    /// <summary>The most bytes HKDF-SHA256 can produce: 255 blocks of 32.</summary>
    public const int MaximumHkdfLength = 255 * 32;

    /// <summary>
    /// Derives key bytes with HKDF-SHA256, extract then expand.
    /// </summary>
    /// <param name="inputKeyMaterial">The secret; not empty.</param>
    /// <param name="salt">The salt; not empty. Sealed frames use SHA-256 of the session transcript.</param>
    /// <param name="info">The purpose label; not empty.</param>
    /// <param name="length">How many bytes to return, 1 to <see cref="MaximumHkdfLength"/>.</param>
    /// <returns>Exactly <paramref name="length"/> bytes.</returns>
    /// <exception cref="ArgumentException">The secret, salt or info is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The length is out of range.</exception>
    public static byte[] Hkdf(ReadOnlySpan<byte> inputKeyMaterial, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int length)
    {
        if (inputKeyMaterial.IsEmpty)
        {
            throw new ArgumentException("The input key material is empty.", nameof(inputKeyMaterial));
        }
        if (salt.IsEmpty)
        {
            throw new ArgumentException("The salt is required.", nameof(salt));
        }
        if (info.IsEmpty)
        {
            throw new ArgumentException("The info label is required, so keys for different purposes differ.", nameof(info));
        }
        ArgumentOutOfRangeException.ThrowIfLessThan(length, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, MaximumHkdfLength);
        byte[] output = new byte[length];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial, output, salt, info);
        return output;
    }

    /// <summary>
    /// Derives key bytes with HKDF-SHA256, with a text label encoded as UTF-8 (for example
    /// <c>BAM-SEALED-FRAME-1 client-to-server</c>).
    /// </summary>
    /// <param name="inputKeyMaterial">The secret; not empty.</param>
    /// <param name="salt">The salt; not empty.</param>
    /// <param name="label">The purpose label; not null, empty or white space, and valid UTF-16.</param>
    /// <param name="length">How many bytes to return, 1 to <see cref="MaximumHkdfLength"/>.</param>
    /// <returns>Exactly <paramref name="length"/> bytes.</returns>
    /// <exception cref="ArgumentException">The secret or salt is empty, or the label is blank or not valid text.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The length is out of range.</exception>
    public static byte[] Hkdf(ReadOnlySpan<byte> inputKeyMaterial, ReadOnlySpan<byte> salt, string label, int length)
    {
        if (string.IsNullOrWhiteSpace(label))
        {
            throw new ArgumentException("The info label is required, so keys for different purposes differ.", nameof(label));
        }
        byte[] info;
        try
        {
            info = new UTF8Encoding(false, true).GetBytes(label);
        }
        catch (EncoderFallbackException)
        {
            throw new ArgumentException("The info label is not valid text (a lone surrogate).", nameof(label));
        }
        return Hkdf(inputKeyMaterial, salt, info, length);
    }
}

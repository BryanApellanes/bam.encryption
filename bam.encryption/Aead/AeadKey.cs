using System.Security.Cryptography;

namespace Bam.Encryption;

/// <summary>
/// An AES-256-GCM key: authenticated encryption with associated data, a 12-byte nonce the caller supplies and a
/// 16-byte tag (bam.encryption#38). Sealed frames (bam.protocol#116) build the nonce with <see cref="SequenceNonce"/>;
/// an at-rest format (bam.encryption#37) uses random nonces on the same type.
/// </summary>
/// <remarks>
/// <para>A nonce must never be used twice with the same key. With sequence nonces, give each key one direction and
/// one counter. With random nonces, keep each key to about 2^32 messages.</para>
/// <para><see cref="Open"/> never returns plaintext unless the tag verifies, and never throws for bad input: it
/// returns <see cref="AeadOpenStatus.Tampered"/> or <see cref="AeadOpenStatus.Malformed"/>.</para>
/// <para>An instance is not safe to use from two threads at once. Dispose it when the session ends.</para>
/// </remarks>
public sealed class AeadKey : IDisposable
{
    /// <summary>The key length in bytes.</summary>
    public const int KeyLength = 32;

    /// <summary>The nonce length in bytes.</summary>
    public const int NonceLength = 12;

    /// <summary>The tag length in bytes, appended to the ciphertext.</summary>
    public const int TagLength = 16;

    private readonly AesGcm aes;
    private bool disposed;

    /// <summary>
    /// Creates a key from its bytes. The bytes are copied; the caller still owns (and should clear) its copy.
    /// </summary>
    /// <param name="key">Exactly <see cref="KeyLength"/> bytes.</param>
    /// <exception cref="ArgumentException">The key is not 32 bytes.</exception>
    /// <exception cref="PlatformNotSupportedException">The platform has no AES-GCM.</exception>
    public AeadKey(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeyLength)
        {
            throw new ArgumentException($"An AES-256-GCM key is {KeyLength} bytes; {key.Length} were given.", nameof(key));
        }
        aes = new AesGcm(key, TagLength);
    }

    /// <summary>
    /// Creates a key from <see cref="RandomNumberGenerator"/>.
    /// </summary>
    /// <returns>The key.</returns>
    public static AeadKey Generate()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(KeyLength);
        try
        {
            return new AeadKey(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Encrypts and authenticates.
    /// </summary>
    /// <param name="nonce"><see cref="NonceLength"/> bytes, never used before with this key.</param>
    /// <param name="plaintext">The plaintext; may be empty.</param>
    /// <param name="associatedData">Data that is authenticated but not encrypted; may be empty.</param>
    /// <returns>The ciphertext with the tag appended.</returns>
    /// <exception cref="ArgumentException">The nonce is not 12 bytes.</exception>
    /// <exception cref="ObjectDisposedException">The key was disposed.</exception>
    public byte[] Seal(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (nonce.Length != NonceLength)
        {
            throw new ArgumentException($"The nonce is {NonceLength} bytes; {nonce.Length} were given.", nameof(nonce));
        }
        byte[] sealedData = new byte[plaintext.Length + TagLength];
        aes.Encrypt(nonce, plaintext, sealedData.AsSpan(0, plaintext.Length), sealedData.AsSpan(plaintext.Length), associatedData);
        return sealedData;
    }

    /// <summary>
    /// Verifies and decrypts.
    /// </summary>
    /// <param name="nonce">The nonce the data was sealed with.</param>
    /// <param name="sealedData">The ciphertext with the tag appended, as <see cref="Seal"/> returns it.</param>
    /// <param name="associatedData">The associated data it was sealed with.</param>
    /// <returns><see cref="AeadOpenStatus.Opened"/> with the plaintext; <see cref="AeadOpenStatus.Tampered"/> when
    /// the tag does not verify (a changed ciphertext, tag, nonce, key or associated data); or
    /// <see cref="AeadOpenStatus.Malformed"/> when the nonce is not 12 bytes or the data is shorter than a tag.</returns>
    /// <exception cref="ObjectDisposedException">The key was disposed.</exception>
    public AeadOpenResult Open(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> sealedData, ReadOnlySpan<byte> associatedData)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (nonce.Length != NonceLength)
        {
            return AeadOpenResult.Malformed($"The nonce is {nonce.Length} bytes, not {NonceLength}.");
        }
        if (sealedData.Length < TagLength)
        {
            return AeadOpenResult.Malformed($"The data is {sealedData.Length} bytes, shorter than the {TagLength}-byte tag.");
        }
        int ciphertextLength = sealedData.Length - TagLength;
        byte[] plaintext = new byte[ciphertextLength];
        try
        {
            aes.Decrypt(nonce, sealedData.Slice(0, ciphertextLength), sealedData.Slice(ciphertextLength), plaintext, associatedData);
        }
        catch (AuthenticationTagMismatchException)
        {
            // AesGcm already clears the output on a mismatch; clear it again so that holds on every platform.
            CryptographicOperations.ZeroMemory(plaintext);
            return AeadOpenResult.Tampered();
        }
        return AeadOpenResult.Opened(plaintext);
    }

    /// <summary>
    /// Releases the key.
    /// </summary>
    public void Dispose()
    {
        if (!disposed)
        {
            disposed = true;
            aes.Dispose();
        }
    }
}

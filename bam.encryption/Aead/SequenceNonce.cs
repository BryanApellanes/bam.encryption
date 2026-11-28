using System.Buffers.Binary;

namespace Bam.Encryption;

/// <summary>
/// The direction a sealed frame travels in, which is also the nonce's 4-byte prefix (bam.protocol#118).
/// </summary>
public enum FrameDirection : uint
{
    /// <summary>Client to server: prefix <c>00000001</c>.</summary>
    ClientToServer = 1,

    /// <summary>Server to client: prefix <c>00000002</c>.</summary>
    ServerToClient = 2,
}

/// <summary>
/// Builds the 12-byte nonce for a frame of a session: 4 bytes of big-endian direction, then 8 bytes of big-endian
/// sequence number (bam.protocol#118, section 5). Each direction has its own key, and the prefix keeps the two
/// directions' nonces apart even if a key were ever shared.
/// </summary>
public static class SequenceNonce
{
    /// <summary>The most frames a sealed-frame session carries in one direction: 2^20. Sequence numbers run from 0
    /// to one less than this.</summary>
    public const ulong SessionFrameLimit = 1UL << 20;

    /// <summary>
    /// Builds a nonce, refusing an unknown direction and a sequence number at or past the limit, so a counter can
    /// never wrap onto a nonce already used.
    /// </summary>
    /// <param name="direction">The frame's direction.</param>
    /// <param name="sequence">The frame's sequence number, from 0.</param>
    /// <param name="limit">How many frames the session allows in this direction, normally
    /// <see cref="SessionFrameLimit"/>.</param>
    /// <param name="nonce">The nonce, or an empty array when refused.</param>
    /// <returns>True when the nonce was built.</returns>
    public static bool TryCreate(FrameDirection direction, ulong sequence, ulong limit, out byte[] nonce)
    {
        if (!Enum.IsDefined(direction) || sequence >= limit)
        {
            nonce = Array.Empty<byte>();
            return false;
        }
        nonce = new byte[AeadKey.NonceLength];
        BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(0, 4), (uint)direction);
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4, 8), sequence);
        return true;
    }

    /// <summary>
    /// Builds a nonce within <see cref="SessionFrameLimit"/>.
    /// </summary>
    /// <param name="direction">The frame's direction.</param>
    /// <param name="sequence">The frame's sequence number, from 0.</param>
    /// <param name="nonce">The nonce, or an empty array when refused.</param>
    /// <returns>True when the nonce was built.</returns>
    public static bool TryCreate(FrameDirection direction, ulong sequence, out byte[] nonce)
    {
        return TryCreate(direction, sequence, SessionFrameLimit, out nonce);
    }
}

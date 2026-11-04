namespace Bam.Encryption.Cose;

/// <summary>
/// Raised when CBOR input is malformed, truncated, uses an encoding the reader refuses
/// (indefinite lengths, duplicate map keys, unsupported key types, integers outside
/// <see cref="long"/>), or exceeds the reader's nesting limit.
/// </summary>
public class CborFormatException : FormatException
{
    /// <summary>
    /// Initializes a new instance with a message and no position.
    /// </summary>
    /// <param name="message">What was wrong.</param>
    public CborFormatException(string message) : base(message)
    {
        Offset = -1;
    }

    /// <summary>
    /// Initializes a new instance with a message and the byte offset where the problem was found.
    /// </summary>
    /// <param name="message">What was wrong.</param>
    /// <param name="offset">The byte offset into the input.</param>
    public CborFormatException(string message, int offset) : base($"{message} (offset {offset})")
    {
        Offset = offset;
    }

    /// <summary>
    /// Gets the byte offset into the input where the problem was found, or -1 when not positional.
    /// </summary>
    public int Offset { get; }
}

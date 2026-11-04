namespace Bam.Encryption.Cose;

/// <summary>
/// Raised when a COSE_Key is missing required parameters, names an unsupported key type, curve
/// or algorithm, or carries key material that is not a valid public key.
/// </summary>
public class CoseKeyException : Exception
{
    /// <summary>
    /// Initializes a new instance with a message.
    /// </summary>
    /// <param name="message">What was wrong.</param>
    public CoseKeyException(string message) : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance with a message and the underlying cause.
    /// </summary>
    /// <param name="message">What was wrong.</param>
    /// <param name="innerException">The underlying cause.</param>
    public CoseKeyException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

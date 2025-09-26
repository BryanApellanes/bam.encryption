namespace Bam.Encryption;

/// <summary>
/// When implemented in a derived class provides keys for
/// use in HMAC calculations.
/// </summary>
public interface IHmacKeyProvider
{
    /// <summary>
    /// Gets new hmac key.
    /// </summary>
    /// <returns></returns>
    byte[] GetNewHmacKey();
    
    /// <summary>
    /// Get the HMAC key with the specified name.
    /// </summary>
    /// <param name="name"></param>
    /// <returns></returns>
    byte[] GetNamedHmacKey(string name);
}
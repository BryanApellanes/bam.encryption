namespace Bam.Encryption;

/// <summary>
/// Defines storage operations for named key material.
/// </summary>
public interface INamedKeyStorage
{
    /// <summary>
    /// Saves key bytes under the specified name.
    /// </summary>
    /// <param name="keyName">The name to associate with the key.</param>
    /// <param name="keyBytes">The raw key bytes to store.</param>
    /// <returns>True if the save succeeded; otherwise, false.</returns>
    bool SaveNamedKey(string keyName, byte[] keyBytes);

    /// <summary>
    /// Retrieves key bytes by name.
    /// </summary>
    /// <param name="name">The name of the key to retrieve.</param>
    /// <returns>The key bytes, or null if not found.</returns>
    byte[]? GetNamedKey(string name);
}

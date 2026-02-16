namespace Bam.Encryption;

/// <summary>
/// Defines storage operations for public keys, indexed by their hash.
/// </summary>
public interface IPublicKeyStorage
{
    /// <summary>
    /// Stores the specified PEM-encoded public key using the default hash algorithm and returns the hash.
    /// </summary>
    /// <param name="pemString">The PEM-encoded public key string to store.</param>
    /// <returns>The hash of the stored public key.</returns>
    string Store(string pemString);

    /// <summary>
    /// Stores the specified PEM-encoded public key using the given hash algorithm and returns the hash.
    /// </summary>
    /// <param name="pemString">The PEM-encoded public key string to store.</param>
    /// <param name="algorithm">The hash algorithm to use for computing the key hash.</param>
    /// <returns>The hash of the stored public key.</returns>
    string Store(string pemString, HashAlgorithms algorithm);

    /// <summary>
    /// Retrieves the PEM-encoded public key associated with the specified hash.
    /// </summary>
    /// <param name="hash">The hash identifying the public key.</param>
    /// <returns>The PEM-encoded public key string.</returns>
    string Retrieve(string hash);

    /// <summary>
    /// Retrieves the PEM-encoded public key associated with the specified hash and algorithm.
    /// </summary>
    /// <param name="hash">The hash identifying the public key.</param>
    /// <param name="algorithm">The hash algorithm used when the key was stored.</param>
    /// <returns>The PEM-encoded public key string.</returns>
    string Retrieve(string hash, HashAlgorithms algorithm);

    /// <summary>
    /// Deletes the public key associated with the specified hash.
    /// </summary>
    /// <param name="hash">The hash identifying the public key to delete.</param>
    /// <returns>True if the key was deleted; otherwise, false.</returns>
    bool Delete(string hash);
}
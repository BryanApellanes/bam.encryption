namespace Bam.Encryption
{
    /// <summary>
    /// Defines a typed encryptor that encrypts data of a specific type and produces typed cipher results.
    /// </summary>
    /// <typeparam name="TData">The type of data to encrypt.</typeparam>
    public interface IEncryptor<TData> : IEncryptor
    {
        /// <summary>
        /// Encrypts the specified data and returns a typed cipher result.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <returns>A cipher containing the encrypted data.</returns>
        Cipher<TData> Encrypt(TData data);

        /// <summary>
        /// Gets a typed decryptor that can decrypt data encrypted by this encryptor.
        /// </summary>
        /// <returns>A typed decryptor instance.</returns>
        new IDecryptor<TData> GetDecryptor();
    }

    /// <summary>
    /// Defines an encryptor that encrypts strings and byte arrays.
    /// </summary>
    public interface IEncryptor
    {
        /// <summary>
        /// Gets a decryptor that can decrypt data encrypted by this encryptor.
        /// </summary>
        /// <returns>A decryptor instance.</returns>
        IDecryptor GetDecryptor();

        /// <summary>
        /// Encrypts the specified plain text string.
        /// </summary>
        /// <param name="plainData">The plain text to encrypt.</param>
        /// <returns>The encrypted string.</returns>
        string Encrypt(string plainData);

        /// <summary>
        /// Encrypts the specified byte array.
        /// </summary>
        /// <param name="plainData">The byte array to encrypt.</param>
        /// <returns>The encrypted byte array.</returns>
        byte[] Encrypt(byte[] plainData);
    }
}

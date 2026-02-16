namespace Bam.Encryption
{
    /// <summary>
    /// Defines a typed decryptor that can decrypt typed cipher objects back to their original form.
    /// </summary>
    /// <typeparam name="TData">The type of data to decrypt.</typeparam>
    public interface IDecryptor<TData> : IDecryptor
    {
        /// <summary>
        /// Decrypts the specified typed cipher back to the original data.
        /// </summary>
        /// <param name="cipherData">The typed cipher to decrypt.</param>
        /// <returns>The decrypted data.</returns>
        TData DecryptCipher(Cipher<TData> cipherData);
    }

    /// <summary>
    /// Defines a decryptor that can decrypt cipher objects, strings, and byte arrays.
    /// </summary>
    public interface IDecryptor
    {
        /// <summary>
        /// Decrypts the specified cipher object to a plain text string.
        /// </summary>
        /// <param name="cipher">The cipher to decrypt.</param>
        /// <returns>The decrypted plain text string.</returns>
        string DecryptCipher(Cipher cipher);

        /// <summary>
        /// Decrypts the specified cipher string.
        /// </summary>
        /// <param name="cipher">The cipher text to decrypt.</param>
        /// <returns>The decrypted plain text string.</returns>
        string Decrypt(string cipher);

        /// <summary>
        /// Decrypts the specified cipher byte array.
        /// </summary>
        /// <param name="cipher">The encrypted byte array.</param>
        /// <returns>The decrypted byte array.</returns>
        byte[] Decrypt(byte[] cipher);
    }
}

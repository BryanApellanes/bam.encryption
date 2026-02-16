namespace Bam.Encryption
{
    /// <summary>
    /// Defines a dictionary that accepts encrypted key-value pairs and provides access to their decrypted values.
    /// </summary>
    public interface IDecryptedDictionary
    {
        /// <summary>
        /// Gets the decryptor used to decrypt keys and values.
        /// </summary>
        IDecryptor Decryptor { get; }

        /// <summary>
        /// Gets or sets the value associated with the specified key.
        /// </summary>
        /// <param name="key">The key to look up or set.</param>
        /// <returns>The value associated with the key.</returns>
        string this[string key] { get; set; }

        /// <summary>
        /// Gets the collection of decrypted keys.
        /// </summary>
        ICollection<string> Keys { get; }

        /// <summary>
        /// Gets the collection of decrypted values.
        /// </summary>
        ICollection<string> Values { get; }

        /// <summary>
        /// Gets the number of entries in the dictionary.
        /// </summary>
        int Count { get; }

        /// <summary>
        /// Adds an encrypted key-value pair.
        /// </summary>
        /// <param name="key">The encrypted key.</param>
        /// <param name="value">The encrypted value.</param>
        void Add(string key, string value);

        /// <summary>
        /// Adds an encrypted key-value pair.
        /// </summary>
        /// <param name="item">The encrypted key-value pair to add.</param>
        void Add(System.Collections.Generic.KeyValuePair<string, string> item);

        /// <summary>
        /// Removes all entries from the dictionary.
        /// </summary>
        void Clear();

        /// <summary>
        /// Determines whether the dictionary contains the specified key-value pair.
        /// </summary>
        /// <param name="item">The key-value pair to locate.</param>
        /// <returns>True if the item is found; otherwise, false.</returns>
        bool Contains(System.Collections.Generic.KeyValuePair<string, string> item);

        /// <summary>
        /// Determines whether the dictionary contains the specified key.
        /// </summary>
        /// <param name="key">The key to locate.</param>
        /// <returns>True if the key is found; otherwise, false.</returns>
        bool ContainsKey(string key);

        /// <summary>
        /// Removes the entry with the specified key.
        /// </summary>
        /// <param name="key">The key to remove.</param>
        /// <returns>True if the entry was removed; otherwise, false.</returns>
        bool Remove(string key);
    }
}

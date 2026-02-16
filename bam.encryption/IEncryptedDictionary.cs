namespace Bam.Encryption
{
    /// <summary>
    /// Defines a dictionary that transparently encrypts and decrypts its values.
    /// </summary>
    public interface IEncryptedDictionary
    {
        /// <summary>
        /// Gets the encryptor used to encrypt and decrypt values.
        /// </summary>
        IEncryptor Encryptor { get; }

        /// <summary>
        /// Gets or sets the value associated with the specified key, encrypting on set and decrypting on get.
        /// </summary>
        /// <param name="key">The key of the value to get or set.</param>
        /// <returns>The decrypted value associated with the specified key.</returns>
        string this[string key] { get; set; }

        /// <summary>
        /// Gets a collection containing the keys in the dictionary.
        /// </summary>
        ICollection<string> Keys { get; }

        /// <summary>
        /// Gets a collection containing the encrypted values in the dictionary.
        /// </summary>
        ICollection<string> Values { get; }

        /// <summary>
        /// Gets the number of key-value pairs in the dictionary.
        /// </summary>
        int Count { get; }

        /// <summary>
        /// Adds the specified key and value to the dictionary, encrypting the value.
        /// </summary>
        /// <param name="key">The key of the element to add.</param>
        /// <param name="value">The value to encrypt and add.</param>
        void Add(string key, string value);

        /// <summary>
        /// Adds the specified key-value pair to the dictionary, encrypting the value.
        /// </summary>
        /// <param name="item">The key-value pair to add.</param>
        void Add(System.Collections.Generic.KeyValuePair<string, string> item);

        /// <summary>
        /// Removes all keys and values from the dictionary.
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
        /// Removes the value with the specified key from the dictionary.
        /// </summary>
        /// <param name="key">The key of the element to remove.</param>
        /// <returns>True if the element was removed; otherwise, false.</returns>
        bool Remove(string key);
    }
}

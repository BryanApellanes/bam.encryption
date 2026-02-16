namespace Bam.Encryption
{
    /// <summary>
    /// A dictionary that stores encrypted key-value pairs and transparently decrypts them on access, maintaining both encrypted and decrypted representations.
    /// </summary>
    public class DecryptedDictionary : IDecryptedDictionary
    {
        private Dictionary<string, string> _unencrypted;
        private Dictionary<string, string> _encrypted;

        /// <summary>
        /// Initializes a new instance of the <see cref="DecryptedDictionary"/> class with the specified decryptor.
        /// </summary>
        /// <param name="decryptor">The decryptor used to decrypt keys and values.</param>
        public DecryptedDictionary(IDecryptor decryptor)
        {
            Args.ThrowIfNull(decryptor);
            this.Decryptor = decryptor;
            this._unencrypted = new Dictionary<string, string>();
            this._encrypted = new Dictionary<string, string>();
        }

        /// <summary>
        /// Creates a <see cref="DecryptedDictionary"/> from a newline-delimited string where each line contains a dot-separated encrypted key-value pair.
        /// </summary>
        /// <param name="decryptor">The decryptor used to decrypt keys and values.</param>
        /// <param name="encryptedDictionaryString">The string containing encrypted key-value pairs separated by newlines and dots.</param>
        /// <returns>A new <see cref="DecryptedDictionary"/> populated with the parsed entries.</returns>
        public static DecryptedDictionary FromString(IDecryptor decryptor, string encryptedDictionaryString)
        {
            DecryptedDictionary decryptedDictionary = new DecryptedDictionary(decryptor);
            string[] lines = encryptedDictionaryString.DelimitSplit("\r", "\n");
            foreach(string line in lines)
            {
                string[] keyValue = line.DelimitSplit(".");
                decryptedDictionary.Add(keyValue[0], keyValue[1]);
            }
            return decryptedDictionary;
        }

        /// <summary>
        /// Gets or sets the value for the specified key. When setting, the encrypted key and value are stored and automatically decrypted.
        /// </summary>
        /// <param name="key">The encrypted key to look up or set.</param>
        /// <returns>The value associated with the key, or null if not found.</returns>
        public string this[string key]
        {
            get
            {
                if (_unencrypted.ContainsKey(key))
                {
                    return _unencrypted[key];
                }
                else if(_encrypted.ContainsKey(key))
                {
                    return _encrypted[key];
                }
                return null;
            }
            set
            {
                if (_encrypted.ContainsKey(key))
                {
                    _encrypted[key] = value;
                }
                else
                {
                    _encrypted.Add(key, value);
                }

                string decryptedKey = this.Decryptor.Decrypt(key);
                string decryptedValue = this.Decryptor.Decrypt(value);
                if(!_unencrypted.ContainsKey(decryptedKey))
                {
                    _unencrypted.Add(decryptedKey, decryptedValue);
                }
                else
                {
                    _unencrypted[decryptedKey] = decryptedValue;
                }
            }
        }

        /// <summary>
        /// Gets the decryptor used to decrypt keys and values in this dictionary.
        /// </summary>
        public IDecryptor Decryptor
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the collection of decrypted keys.
        /// </summary>
        public ICollection<string> Keys => _unencrypted.Keys;

        /// <summary>
        /// Gets the collection of decrypted values.
        /// </summary>
        public ICollection<string> Values => _unencrypted.Values;

        /// <summary>
        /// Gets the number of entries in the dictionary.
        /// </summary>
        public int Count => _unencrypted.Count;

        /// <summary>
        /// Adds an encrypted key-value pair, which will be decrypted and stored.
        /// </summary>
        /// <param name="key">The encrypted key.</param>
        /// <param name="value">The encrypted value.</param>
        public void Add(string key, string value)
        {
            this[key] = value;
        }

        /// <summary>
        /// Adds an encrypted key-value pair from a KeyValuePair, which will be decrypted and stored.
        /// </summary>
        /// <param name="item">The encrypted key-value pair to add.</param>
        public void Add(System.Collections.Generic.KeyValuePair<string, string> item)
        {
            this.Add(item.Key, item.Value);
        }

        /// <summary>
        /// Removes all entries from both the encrypted and decrypted dictionaries.
        /// </summary>
        public void Clear()
        {
            this._encrypted.Clear();
            this._unencrypted.Clear();
        }

        /// <summary>
        /// Determines whether the dictionary contains the specified key-value pair, checking both encrypted and decrypted stores.
        /// </summary>
        /// <param name="item">The key-value pair to locate.</param>
        /// <returns>True if the item is found; otherwise, false.</returns>
        public bool Contains(System.Collections.Generic.KeyValuePair<string, string> item)
        {
            if (this._encrypted.ContainsKey(item.Key))
            {
                return this._encrypted[item.Key] == item.Value;
            }

            if (this._unencrypted.ContainsKey(item.Key))
            {
                return this._unencrypted[item.Key] == item.Value;
            }

            return false;
        }

        /// <summary>
        /// Determines whether the dictionary contains the specified key in either the encrypted or decrypted store.
        /// </summary>
        /// <param name="key">The key to locate.</param>
        /// <returns>True if the key is found; otherwise, false.</returns>
        public bool ContainsKey(string key)
        {
            return this._encrypted.ContainsKey(key) || this._unencrypted.ContainsKey(key);
        }

        /// <summary>
        /// Removes the entry with the specified key from the dictionary.
        /// </summary>
        /// <param name="key">The key to remove.</param>
        /// <returns>True if the entry was found and removed; otherwise, false.</returns>
        public bool Remove(string key)
        {
            if (this._encrypted.ContainsKey(key))
            {
                return this._encrypted.Remove(key);
            }
            if (this._unencrypted.ContainsKey(key))
            {
                return this._unencrypted.Remove(key);
            }

            return false;
        }
    }
}

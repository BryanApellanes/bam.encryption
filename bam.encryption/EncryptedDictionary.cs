using System.Text;

namespace Bam.Encryption
{
    /// <summary>
    /// A dictionary that stores plain text key-value pairs and automatically encrypts them, maintaining both encrypted and unencrypted representations.
    /// </summary>
    public class EncryptedDictionary : IEncryptedDictionary
    {
        private Dictionary<string, string> _unencrypted;
        private Dictionary<string, string> _encrypted;
        private Dictionary<string, string> _encryptedValues;

        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedDictionary"/> class with the specified encryptor.
        /// </summary>
        /// <param name="encryptor">The encryptor used to encrypt keys and values.</param>
        public EncryptedDictionary(IEncryptor encryptor)
        {
            Args.ThrowIfNull(encryptor);
            this.Encryptor = encryptor;
            this._unencrypted = new Dictionary<string, string>();
            this._encrypted = new Dictionary<string, string>();
            this._encryptedValues = new Dictionary<string, string>();
        }

        /// <summary>
        /// Returns a string representation of the encrypted dictionary with each entry on a new line in the format "encryptedKey.encryptedValue".
        /// </summary>
        /// <returns>A newline-delimited string of encrypted key-value pairs.</returns>
        public override string ToString()
        {
            StringBuilder output = new StringBuilder();
            foreach(string key in this._encrypted.Keys)
            {
                output.AppendLine($"{key}.{this._encrypted[key]}");
            }
            return output.ToString();
        }

        /// <summary>
        /// Gets the encrypted value for the specified plain text key, or sets a plain text key-value pair which is automatically encrypted.
        /// </summary>
        /// <param name="key">The plain text key.</param>
        /// <returns>The encrypted value for the key, or null if not found.</returns>
        public string this[string key]
        {
            get
            {
                if(_encryptedValues.ContainsKey(key))
                {
                    return _encryptedValues[key];
                }
                else if (_encrypted.ContainsKey(key))
                {
                    return _encrypted[key];
                }
                else if (_unencrypted.ContainsKey(key))
                {
                    return _unencrypted[key];
                }
                
                return null!;
            }

            set
            {
                if (_unencrypted.ContainsKey(key))
                {
                    _unencrypted[key] = value;
                }
                else
                {
                    _unencrypted.Add(key, value);
                }

                string encryptedKey = this.Encryptor.Encrypt(key);
                string encryptedValue = this.Encryptor.Encrypt(value);
                if (!_encrypted.ContainsKey(encryptedKey))
                {
                    _encrypted.Add(encryptedKey, encryptedValue);
                }
                else
                {
                    _encrypted[encryptedKey] = encryptedValue;
                }

                if (!_encryptedValues.ContainsKey(key))
                {
                    _encryptedValues.Add(key, encryptedValue);
                }
                else
                {
                    _encryptedValues[key] = encryptedValue;
                }
            }
        }

        /// <summary>
        /// Gets the encryptor used to encrypt keys and values in this dictionary.
        /// </summary>
        public IEncryptor Encryptor
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the collection of encrypted keys.
        /// </summary>
        public ICollection<string> Keys => _encrypted.Keys;

        /// <summary>
        /// Gets the collection of encrypted values.
        /// </summary>
        public ICollection<string> Values => _encrypted.Values;

        /// <summary>
        /// Gets the number of entries in the dictionary.
        /// </summary>
        public int Count => _encrypted.Count;

        /// <summary>
        /// Adds a plain text key-value pair, which will be automatically encrypted.
        /// </summary>
        /// <param name="key">The plain text key.</param>
        /// <param name="value">The plain text value.</param>
        public void Add(string key, string value)
        {
            this[key] = value;
        }

        /// <summary>
        /// Adds a plain text key-value pair from a KeyValuePair, which will be automatically encrypted.
        /// </summary>
        /// <param name="item">The plain text key-value pair to add.</param>
        public void Add(System.Collections.Generic.KeyValuePair<string, string> item)
        {
            this.Add(item.Key, item.Value);
        }

        /// <summary>
        /// Removes all entries from the unencrypted, encrypted, and encrypted-values dictionaries.
        /// </summary>
        public void Clear()
        {
            this._unencrypted.Clear();
            this._encrypted.Clear();
            this._encryptedValues.Clear();
        }

        /// <summary>
        /// Determines whether the dictionary contains the specified key-value pair, checking both unencrypted and encrypted stores.
        /// </summary>
        /// <param name="item">The key-value pair to locate.</param>
        /// <returns>True if the item is found; otherwise, false.</returns>
        public bool Contains(System.Collections.Generic.KeyValuePair<string, string> item)
        {
            if (this._unencrypted.ContainsKey(item.Key))
            {
                return this._unencrypted[item.Key] == item.Value;
            }

            if (this._encrypted.ContainsKey(item.Key))
            {
                return this._encrypted[item.Key] == item.Value;
            }

            return false;
        }

        /// <summary>
        /// Determines whether the dictionary contains the specified key in either the unencrypted or encrypted store.
        /// </summary>
        /// <param name="key">The key to locate.</param>
        /// <returns>True if the key is found; otherwise, false.</returns>
        public bool ContainsKey(string key)
        {
            return this._unencrypted.ContainsKey(key) || this._encrypted.ContainsKey(key);
        }

        /// <summary>
        /// Removes the entry with the specified key from all internal dictionaries.
        /// </summary>
        /// <param name="key">The key to remove.</param>
        /// <returns>True if the entry was found and removed from at least one internal dictionary; otherwise, false.</returns>
        public bool Remove(string key)
        {
            bool result = false;
            if (this._unencrypted.ContainsKey(key))
            {
                result = this._unencrypted.Remove(key);
            }
            if (this._encrypted.ContainsKey(key))
            {
                result = this._encrypted.Remove(key);
            }
            if (this._encryptedValues.ContainsKey(key))
            {
                result = this._encryptedValues.Remove(key);
            }

            return result;
        }
    }
}

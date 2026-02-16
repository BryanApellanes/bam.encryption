namespace Bam.Encryption
{
    /// <summary>
    /// Decrypts data using AES symmetric encryption with a key obtained from a configurable provider.
    /// </summary>
    public class AesDecryptor : IDecryptor
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AesDecryptor"/> class using an AES key source.
        /// </summary>
        /// <param name="aesKeySource">The AES key source to retrieve the key from.</param>
        public AesDecryptor(IAesKeySource aesKeySource)
        {
            this.KeyProvider = () => aesKeySource.GetAesKey();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesDecryptor"/> class using a key provider function.
        /// </summary>
        /// <param name="keyProvider">A function that returns the AES key to use for decryption.</param>
        public AesDecryptor(Func<AesKey> keyProvider)
        {
            this.KeyProvider = keyProvider;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesDecryptor"/> class using a specific AES key.
        /// </summary>
        /// <param name="aesKey">The AES key to use for decryption.</param>
        public AesDecryptor(AesKey aesKey)
        {
            this.KeyProvider = () => aesKey;
        }

        /// <summary>
        /// Gets or sets the function that provides the AES key for decryption.
        /// </summary>
        public Func<AesKey> KeyProvider { get; set; }

        /// <summary>
        /// Decrypts the specified cipher object to a plain text string.
        /// </summary>
        /// <param name="cipher">The cipher object containing encrypted data.</param>
        /// <returns>The decrypted plain text string.</returns>
        public string DecryptCipher(Cipher cipher)
        {
            return Decrypt(cipher.ToString());
        }

        /// <summary>
        /// Decrypts the specified Base64-encoded cipher string to plain text.
        /// </summary>
        /// <param name="cipher">The Base64-encoded cipher text to decrypt.</param>
        /// <returns>The decrypted plain text string.</returns>
        public string Decrypt(string cipher)
        {
            AesKey aesKey = KeyProvider();
            return aesKey.Decrypt(cipher);
        }

        /// <summary>
        /// Decrypts the specified encrypted byte array.
        /// </summary>
        /// <param name="cipher">The encrypted byte array to decrypt.</param>
        /// <returns>The decrypted byte array.</returns>
        public byte[] Decrypt(byte[] cipher)
        {
            AesKey aesKey = KeyProvider();
            return aesKey.DecryptBytes(cipher);
        }
    }
}

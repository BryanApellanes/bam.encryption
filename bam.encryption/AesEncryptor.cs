namespace Bam.Encryption
{
    /// <summary>
    /// Encrypts data using AES symmetric encryption with a key obtained from a configurable provider.
    /// </summary>
    public class AesEncryptor : IEncryptor
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AesEncryptor"/> class using an AES key source.
        /// </summary>
        /// <param name="keySource">The AES key source to retrieve the key from.</param>
        public AesEncryptor(IAesKeySource keySource)
        {
            this.KeyProvider = () => keySource.GetAesKey();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesEncryptor"/> class using a key provider function.
        /// </summary>
        /// <param name="keyProvider">A function that returns the AES key to use for encryption.</param>
        public AesEncryptor(Func<AesKey> keyProvider)
        {
            this.KeyProvider = keyProvider;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesEncryptor"/> class using a specific AES key.
        /// </summary>
        /// <param name="aesKey">The AES key to use for encryption.</param>
        public AesEncryptor(AesKey aesKey)
        {
            this.KeyProvider = () => aesKey;
        }

        /// <summary>
        /// Gets or sets the function that provides the AES key for encryption.
        /// </summary>
        public Func<AesKey> KeyProvider { get; set; }

        /// <summary>
        /// Creates a new <see cref="AesDecryptor"/> using the same key provider.
        /// </summary>
        /// <returns>A new decryptor instance for the same key.</returns>
        public IDecryptor GetDecryptor()
        {
            return new AesDecryptor(this.KeyProvider);
        }

        /// <summary>
        /// Encrypts the specified plain text string using AES.
        /// </summary>
        /// <param name="plainData">The plain text to encrypt.</param>
        /// <returns>A Base64-encoded string representing the encrypted value.</returns>
        public string Encrypt(string plainData)
        {
            AesKey aesKey = KeyProvider();
            return aesKey.Encrypt(plainData);
        }

        /// <summary>
        /// Encrypts the specified byte array using AES.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The encrypted byte array.</returns>
        public byte[] Encrypt(byte[] plainData)
        {
            AesKey aesKey = KeyProvider();
            return aesKey.EncryptBytes(plainData);            
        }
    }
}

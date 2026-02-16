namespace Bam.Encryption
{
    /// <summary>
    /// Transforms plain text strings to Base64-encoded AES-encrypted strings and vice versa.
    /// </summary>
    public class AesBase64Transformer : ValueTransformer<string, string>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AesBase64Transformer"/> class using a key provider function.
        /// </summary>
        /// <param name="keyProvider">A function that returns the AES key to use for encryption.</param>
        public AesBase64Transformer(Func<AesKey> keyProvider)
        {
            this.KeyProvider = keyProvider;
            this.AesBase64ReverseTransformer = new AesBase64ReverseTransformer(this);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesBase64Transformer"/> class using an AES key source.
        /// </summary>
        /// <param name="aesKeySource">The AES key source to retrieve the key from.</param>
        public AesBase64Transformer(IAesKeySource aesKeySource) : this(() => aesKeySource.GetAesKey())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesBase64Transformer"/> class using a specific AES key.
        /// </summary>
        /// <param name="aesKey">The AES key to use for encryption.</param>
        public AesBase64Transformer(AesKey aesKey) : this(() => aesKey)
        {
        }

        /// <summary>
        /// Gets the reverse transformer used for decryption.
        /// </summary>
        public AesBase64ReverseTransformer AesBase64ReverseTransformer { get; }

        /// <summary>
        /// Gets or sets the function that provides the AES key for encryption.
        /// </summary>
        public Func<AesKey> KeyProvider { get; set; }

        /// <summary>
        /// Decrypts a Base64-encoded cipher string back to plain text by delegating to the reverse transformer.
        /// </summary>
        /// <param name="base64Cipher">The Base64-encoded cipher text to decrypt.</param>
        /// <returns>The decrypted plain text string.</returns>
        public override string ReverseTransform(string base64Cipher)
        {
            return GetReverseTransformer().ReverseTransform(base64Cipher);
        }

        /// <summary>
        /// Encrypts the specified plain text to a Base64-encoded AES cipher string.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <returns>A Base64-encoded string representing the encrypted value.</returns>
        public override string Transform(string plainText)
        {
            AesKey aesKey = KeyProvider();
            return aesKey.Encrypt(plainText);
        }

        /// <summary>
        /// Gets the reverse transformer used for decryption.
        /// </summary>
        /// <returns>The <see cref="AesBase64ReverseTransformer"/> instance.</returns>
        public override IValueReverseTransformer<string, string> GetReverseTransformer()
        {
            return this.AesBase64ReverseTransformer;
        }
    }
}

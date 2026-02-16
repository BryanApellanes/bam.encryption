namespace Bam.Encryption
{
    /// <summary>
    /// Decrypts data using RSA asymmetric decryption with a private key.
    /// </summary>
    public class RsaDecryptor : IDecryptor
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaDecryptor"/> class with the specified RSA key source.
        /// </summary>
        /// <param name="rsaKeySource">The source that provides the RSA key pair.</param>
        public RsaDecryptor(IRsaKeySource rsaKeySource)
        {
            this.KeyProvider = () => rsaKeySource.GetRsaKey();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaDecryptor"/> class with the specified key provider function.
        /// </summary>
        /// <param name="keyProvider">A function that provides the RSA key pair for decryption.</param>
        public RsaDecryptor(Func<RsaPublicPrivateKeyPair> keyProvider)
        {
            this.KeyProvider = keyProvider;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaDecryptor"/> class with the specified RSA key pair.
        /// </summary>
        /// <param name="rsaPublicPrivateKeyPair">The RSA key pair to use for decryption.</param>
        public RsaDecryptor(RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair)
        {
            this.KeyProvider = () => rsaPublicPrivateKeyPair;
        }

        /// <summary>
        /// Gets or sets the function that provides the RSA key pair for decryption.
        /// </summary>
        public Func<RsaPublicPrivateKeyPair> KeyProvider { get; set; }

        /// <inheritdoc />
        public string DecryptCipher(Cipher cipher)
        {
            return Decrypt(cipher.ToString());
        }

        /// <inheritdoc />
        public string Decrypt(string cipher)
        {
            RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair = KeyProvider();
            return rsaPublicPrivateKeyPair.Decrypt(cipher);
        }

        /// <inheritdoc />
        public byte[] Decrypt(byte[] cipher)
        {
            RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair = KeyProvider();
            return rsaPublicPrivateKeyPair.Decrypt(cipher);
        }
    }
}

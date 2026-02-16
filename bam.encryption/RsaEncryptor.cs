namespace Bam.Encryption
{
    /// <summary>
    /// Encrypts data using RSA asymmetric encryption with a public key.
    /// </summary>
    public class RsaEncryptor : IEncryptor
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaEncryptor"/> class with the specified RSA key source.
        /// </summary>
        /// <param name="rsaKeySource">The source that provides the RSA key pair.</param>
        public RsaEncryptor(IRsaKeySource rsaKeySource)
        {
            this.KeyProvider = () => rsaKeySource.GetRsaKey();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaEncryptor"/> class with the specified key provider function.
        /// </summary>
        /// <param name="keyProvider">A function that provides the RSA key pair for encryption.</param>
        public RsaEncryptor(Func<RsaPublicPrivateKeyPair> keyProvider)
        {
            this.KeyProvider = keyProvider;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaEncryptor"/> class with the specified RSA key pair.
        /// </summary>
        /// <param name="rsaPublicPrivateKeyPair">The RSA key pair to use for encryption.</param>
        public RsaEncryptor(RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair)
        {
            this.KeyProvider = () => rsaPublicPrivateKeyPair;
        }

        /// <summary>
        /// Gets or sets the function that provides the RSA key pair for encryption.
        /// </summary>
        public Func<RsaPublicPrivateKeyPair> KeyProvider { get; set; }

        /// <inheritdoc />
        public IDecryptor GetDecryptor()
        {
            return new RsaDecryptor(this.KeyProvider);
        }

        /// <inheritdoc />
        public string Encrypt(string plainData)
        {
            RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair = KeyProvider();
            return rsaPublicPrivateKeyPair.Encrypt(plainData);
        }

        /// <inheritdoc />
        public byte[] Encrypt(byte[] plainData)
        {
            RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair = KeyProvider();
            return rsaPublicPrivateKeyPair.Encrypt(plainData);
        }
    }
}

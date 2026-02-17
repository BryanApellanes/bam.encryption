namespace Bam.Encryption
{
    /// <summary>
    /// Value transformer that encrypts and decrypts byte arrays using RSA public/private key encryption.
    /// </summary>
    [PipelineFactoryTransformerName("rsa")]
    public class RsaByteTransformer : ValueTransformer<byte[], byte[]>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaByteTransformer"/> class with separate public and private key providers.
        /// </summary>
        /// <param name="publicKeyProvider">A function that provides the RSA public key for encryption.</param>
        /// <param name="privateKeyProvider">A function that provides the RSA key pair for decryption.</param>
        public RsaByteTransformer(Func<RsaPublicKey> publicKeyProvider, Func<RsaPublicPrivateKeyPair> privateKeyProvider)
        {
            this.KeyProvider = publicKeyProvider;
            this.RsaByteReverseTransformer = new RsaByteReverseTransformer(this, privateKeyProvider);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaByteTransformer"/> class with the specified RSA key pair.
        /// </summary>
        /// <param name="rsaPublicPrivateKeyPair">The RSA key pair to use for both encryption and decryption.</param>
        public RsaByteTransformer(RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair) : this(() => rsaPublicPrivateKeyPair.GetRsaPublicKey(), () => rsaPublicPrivateKeyPair)
        { 
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaByteTransformer"/> class from separate public and private key sources.
        /// </summary>
        /// <param name="rsaKeySource">The source of the RSA public key.</param>
        /// <param name="rsaPublicPrivateKeySource">The source of the RSA key pair for decryption.</param>
        [PipelineFactoryConstructor]
        public RsaByteTransformer(IRsaPublicKeySource rsaKeySource, IRsaKeySource rsaPublicPrivateKeySource) : this(() => rsaKeySource.GetRsaPublicKey(), () => rsaPublicPrivateKeySource.GetRsaKey())
        { 
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaByteTransformer"/> class with a public key provider for encryption only.
        /// </summary>
        /// <param name="publicKeyProvider">A function that provides the RSA public key.</param>
        public RsaByteTransformer(Func<RsaPublicKey> publicKeyProvider)
        {
            this.KeyProvider = publicKeyProvider;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaByteTransformer"/> class with the specified RSA public key source.
        /// </summary>
        /// <param name="rsaPublicKeySource">The source of the RSA public key.</param>
        public RsaByteTransformer(IRsaPublicKeySource rsaPublicKeySource) : this(() => rsaPublicKeySource.GetRsaPublicKey())
        {
        }

        /// <summary>
        /// Gets or sets the function that provides the RSA public key for encryption.
        /// </summary>
        public Func<RsaPublicKey> KeyProvider { get; set; }

        /// <summary>
        /// Gets or sets the paired reverse RSA byte transformer for decryption.
        /// </summary>
        public RsaByteReverseTransformer RsaByteReverseTransformer { get; set; } = null!;

        /// <inheritdoc />
        public override byte[] ReverseTransform(byte[] cipherBytes)
        {
            return GetReverseTransformer()!.ReverseTransform(cipherBytes)!;
        }

        /// <inheritdoc />
        public override byte[] Transform(byte[] plainData)
        {
            Args.ThrowIfNull(KeyProvider, "KeyProvider");
            RsaPublicKey rsaKey = KeyProvider();
            return rsaKey.EncryptBytes(plainData);
        }

        /// <inheritdoc />
        public override IValueReverseTransformer<byte[], byte[]> GetReverseTransformer()
        {
            Args.ThrowIfNull(this.RsaByteReverseTransformer);
            return this.RsaByteReverseTransformer;
        }
    }
}

//using Bam.ServiceProxy.Data.Dao.Repository;

namespace Bam.Encryption
{
    /// <summary>
    /// Transforms byte arrays using AES symmetric encryption and decryption. Registered as the "aes" pipeline factory transformer.
    /// </summary>
    [PipelineFactoryTransformerName("aes")]
    public class AesByteTransformer : ValueTransformer<byte[], byte[]>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AesByteTransformer"/> class using a key provider function.
        /// </summary>
        /// <param name="keyProvider">A function that returns the AES key to use for encryption.</param>
        public AesByteTransformer(Func<AesKey> keyProvider)
        {
            this.AesByteReverseTransformer = new AesByteReverseTransformer(this);
            this.KeyProvider = keyProvider;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesByteTransformer"/> class using an AES key source. This is the pipeline factory constructor.
        /// </summary>
        /// <param name="aesKeySource">The AES key source to retrieve the key from.</param>
        [PipelineFactoryConstructor]
        public AesByteTransformer(IAesKeySource aesKeySource) : this(aesKeySource.GetAesKey)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesByteTransformer"/> class using a specific AES key.
        /// </summary>
        /// <param name="aesKey">The AES key to use for encryption.</param>
        public AesByteTransformer(AesKey aesKey) : this(() => aesKey)
        {
        }

        AesByteReverseTransformer _aesByteUntransformer = null!;
        protected AesByteReverseTransformer AesByteReverseTransformer 
        {
            get
            {
                if (this._aesByteUntransformer == null)
                {
                    this._aesByteUntransformer = new AesByteReverseTransformer(this);
                }

                return this._aesByteUntransformer;
            }

            set
            {
                this._aesByteUntransformer = value;
            }
        }

        /// <summary>
        /// Gets or sets the function that provides the AES key for encryption.
        /// </summary>
        public Func<AesKey> KeyProvider { get; set; }

        /// <summary>
        /// Decrypts the specified cipher bytes by delegating to the reverse transformer.
        /// </summary>
        /// <param name="cipherBytes">The encrypted byte array to decrypt.</param>
        /// <returns>The decrypted byte array.</returns>
        public override byte[] ReverseTransform(byte[] cipherBytes)
        {
            return GetReverseTransformer()!.ReverseTransform(cipherBytes)!;
        }

        /// <summary>
        /// Encrypts the specified plain data byte array using AES.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The encrypted byte array.</returns>
        public override byte[] Transform(byte[] plainData)
        {
            Args.ThrowIfNull(KeyProvider, nameof(KeyProvider));
            AesKey aesKey = KeyProvider();

            return aesKey.EncryptBytes(plainData);
        }

        /// <summary>
        /// Gets the reverse transformer used for decryption.
        /// </summary>
        /// <returns>The <see cref="AesByteReverseTransformer"/> instance.</returns>
        public override IValueReverseTransformer<byte[], byte[]> GetReverseTransformer()
        {
            return this.AesByteReverseTransformer;
        }
    }
}

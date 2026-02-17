using Bam.ServiceProxy;
//using Bam.ServiceProxy.Data;

namespace Bam.Encryption
{
    /// <summary>
    /// Reverses AES byte encryption, decrypting cipher bytes back to plain data. Serves as the decryption counterpart to <see cref="AesByteTransformer"/>.
    /// </summary>
    public class AesByteReverseTransformer : IValueReverseTransformer<byte[], byte[]>, IRequiresHttpContext, ICloneable, IContextCloneable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AesByteReverseTransformer"/> class.
        /// </summary>
        /// <param name="aesByteTransformer">The byte transformer whose key provider will be used for decryption.</param>
        public AesByteReverseTransformer(AesByteTransformer aesByteTransformer)
        {
            this.AesByteTransformer = aesByteTransformer;
        }


        Func<AesKey> _keyProvider = null!;
        /// <summary>
        /// Gets or sets the function that provides the AES key for decryption. Falls back to the associated transformer's key provider if not set.
        /// </summary>
        public Func<AesKey> KeyProvider
        {
            get
            {
                if (_keyProvider == null)
                {
                    if (this.AesByteTransformer != null && this.AesByteTransformer.KeyProvider != null)
                    {
                        this._keyProvider = this.AesByteTransformer.KeyProvider;
                    }
                }
                return _keyProvider!;
            }
            set
            {
                _keyProvider = value;
            }
        }

        /// <summary>
        /// Gets or sets the HTTP context for context-aware cloning.
        /// </summary>
        public IHttpContext HttpContext { get; set; } = null!;

        protected AesByteTransformer AesByteTransformer
        {
            get;
            set;
        }

        /// <summary>
        /// Creates a shallow clone of this instance, copying properties and event handlers.
        /// </summary>
        /// <returns>A new cloned instance.</returns>
        public object Clone()
        {
            object clone = new AesByteReverseTransformer(AesByteTransformer);
            clone.CopyProperties(this);
            clone.CopyEventHandlers(this);
            return clone;
        }

        /// <summary>
        /// Creates a shallow clone of this instance with the specified HTTP context.
        /// </summary>
        /// <param name="context">The HTTP context to assign to the clone.</param>
        /// <returns>A new cloned instance with the given HTTP context.</returns>
        public object Clone(IHttpContext context)
        {
            AesByteReverseTransformer clone = new AesByteReverseTransformer(AesByteTransformer);
            clone.CopyProperties(this);
            clone.CopyEventHandlers(this);
            clone.HttpContext = context;
            return clone;
        }

        /// <summary>
        /// Creates a clone using the current HTTP context.
        /// </summary>
        /// <returns>A new cloned instance with the current HTTP context.</returns>
        public object CloneInContext()
        {
            return Clone(HttpContext);
        }

        /// <summary>
        /// Decrypts the specified AES-encrypted byte array back to plain data.
        /// </summary>
        /// <param name="cipherBytes">The encrypted byte array to decrypt.</param>
        /// <returns>The decrypted byte array.</returns>
        public byte[] ReverseTransform(byte[] cipherBytes)
        {
            Args.ThrowIfNull(KeyProvider, nameof(KeyProvider));
            AesKey aesKey = KeyProvider();

            return aesKey.DecryptBytes(cipherBytes);
        }

        /// <summary>
        /// Gets the forward transformer (encryptor) associated with this reverse transformer.
        /// </summary>
        /// <returns>The <see cref="AesByteTransformer"/> used for encryption.</returns>
        public IValueTransformer<byte[], byte[]> GetTransformer()
        {
            return this.AesByteTransformer;
        }
    }
}

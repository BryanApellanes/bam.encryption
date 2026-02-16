using Bam.ServiceProxy;
//using Bam.ServiceProxy.Data;

namespace Bam.Encryption
{
    /// <summary>
    /// Reverse value transformer that decrypts byte arrays using RSA private key decryption.
    /// </summary>
    public class RsaByteReverseTransformer : IValueReverseTransformer<byte[], byte[]>, IRequiresHttpContext, ICloneable, IContextCloneable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaByteReverseTransformer"/> class with the specified key provider.
        /// </summary>
        /// <param name="keyProvider">A function that provides the RSA key pair for decryption.</param>
        public RsaByteReverseTransformer(Func<RsaPublicPrivateKeyPair> keyProvider)
        {
            this.KeyProvider = keyProvider;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaByteReverseTransformer"/> class with a paired forward transformer and key provider.
        /// </summary>
        /// <param name="rsaByteReverseTransformer">The paired forward RSA byte transformer.</param>
        /// <param name="keyProvider">A function that provides the RSA key pair for decryption.</param>
        public RsaByteReverseTransformer(RsaByteTransformer rsaByteReverseTransformer, Func<RsaPublicPrivateKeyPair> keyProvider)
        {
            this.RsaByteTransformer = rsaByteReverseTransformer;
            this.KeyProvider = keyProvider;
        }

        /// <summary>
        /// Gets or sets the function that provides the RSA key pair.
        /// </summary>
        public Func<RsaPublicPrivateKeyPair> KeyProvider { get; set; }

        /// <summary>
        /// Gets or sets the paired forward RSA byte transformer.
        /// </summary>
        public RsaByteTransformer RsaByteTransformer { get; set; }

        /// <summary>
        /// Gets or sets the HTTP context for context-aware cloning.
        /// </summary>
        public IHttpContext HttpContext { get; set; }

        /// <inheritdoc />
        public object Clone()
        {
            object clone = new RsaByteReverseTransformer(RsaByteTransformer, KeyProvider);
            clone.CopyProperties(this);
            clone.CopyEventHandlers(this);
            return clone;
        }

        /// <summary>
        /// Creates a clone of this transformer bound to the specified HTTP context.
        /// </summary>
        /// <param name="context">The HTTP context to bind the clone to.</param>
        /// <returns>A new cloned instance bound to the specified context.</returns>
        public object Clone(IHttpContext context)
        {
            RsaByteReverseTransformer clone = new RsaByteReverseTransformer(RsaByteTransformer, KeyProvider);
            clone.CopyProperties(this);
            clone.CopyEventHandlers(this);
            clone.HttpContext = context;
            return clone;
        }

        /// <inheritdoc />
        public object CloneInContext()
        {
            return Clone(HttpContext);
        }

        /// <summary>
        /// Decrypts the specified cipher bytes using the RSA private key.
        /// </summary>
        /// <param name="cipherBytes">The encrypted byte array to decrypt.</param>
        /// <returns>The decrypted byte array.</returns>
        public byte[] ReverseTransform(byte[] cipherBytes)
        {
            RsaPublicPrivateKeyPair rsaKey = KeyProvider();

            return rsaKey.Decrypt(cipherBytes);
        }

        /// <summary>
        /// Gets the paired forward RSA byte transformer.
        /// </summary>
        /// <returns>The forward transformer.</returns>
        public IValueTransformer<byte[], byte[]> GetTransformer()
        {
            Args.ThrowIfNull(this.RsaByteTransformer);

            return this.RsaByteTransformer;
        }
    }
}

using Bam.ServiceProxy;
//using Bam.ServiceProxy.Data;
using System.Text;

namespace Bam.Encryption
{
    /// <summary>
    /// Reverse value transformer that decrypts Base64-encoded strings using RSA private key decryption.
    /// </summary>
    public class RsaBase64ReverseTransformer : IValueReverseTransformer<string, string>, IRequiresHttpContext, ICloneable, IContextCloneable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaBase64ReverseTransformer"/> class from a paired forward transformer.
        /// </summary>
        /// <param name="transformer">The paired forward RSA Base64 transformer.</param>
        public RsaBase64ReverseTransformer(RsaBase64Transformer transformer)
        {
            this.RsaBase64Transformer = transformer;
            this.KeyProvider = transformer.KeyProvider;
        }

        /// <summary>
        /// Gets or sets the paired forward RSA Base64 transformer.
        /// </summary>
        protected RsaBase64Transformer RsaBase64Transformer { get; set; }

        /// <summary>
        /// Gets or sets the function that provides the RSA key pair.
        /// </summary>
        public Func<RsaPublicPrivateKeyPair> KeyProvider { get; set; }

        /// <summary>
        /// Gets or sets the character encoding to use for string conversion.
        /// </summary>
        public Encoding Encoding { get; set; } = null!;

        /// <summary>
        /// Gets or sets the HTTP context for context-aware cloning.
        /// </summary>
        public IHttpContext HttpContext { get; set; } = null!;

        /// <inheritdoc />
        public object Clone()
        {
            object clone = new RsaBase64ReverseTransformer(RsaBase64Transformer);
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
            RsaBase64ReverseTransformer clone = new RsaBase64ReverseTransformer(RsaBase64Transformer);
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
        /// Decrypts the specified Base64-encoded cipher text using the RSA private key.
        /// </summary>
        /// <param name="base64Cipher">The Base64-encoded cipher text to decrypt.</param>
        /// <returns>The decrypted plain text.</returns>
        public string ReverseTransform(string base64Cipher)
        {
            RsaPublicPrivateKeyPair rsaKey = KeyProvider();
            return rsaKey.Decrypt(base64Cipher, Encoding);
        }

        /// <summary>
        /// Gets the paired forward RSA Base64 transformer.
        /// </summary>
        /// <returns>The forward transformer.</returns>
        public IValueTransformer<string, string> GetTransformer()
        {
            return this.RsaBase64Transformer;
        }
    }
}

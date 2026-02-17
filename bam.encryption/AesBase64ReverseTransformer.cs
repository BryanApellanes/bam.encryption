using Bam.ServiceProxy;
//using Bam.ServiceProxy.Data;
using System.Text;

namespace Bam.Encryption
{
    /// <summary>
    /// Reverses an AES Base64-encoded cipher back to plain text. Serves as the decryption counterpart to <see cref="AesBase64Transformer"/>.
    /// </summary>
    public class AesBase64ReverseTransformer : IValueReverseTransformer<string, string>, IRequiresHttpContext, ICloneable, IContextCloneable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AesBase64ReverseTransformer"/> class.
        /// </summary>
        /// <param name="aesBase64Transformer">The transformer whose key provider will be used for decryption.</param>
        /// <param name="encoding">The text encoding to use. Defaults to UTF-8.</param>
        public AesBase64ReverseTransformer(AesBase64Transformer aesBase64Transformer, Encoding? encoding = null)
        {
            this.AesBase64Transformer = aesBase64Transformer;
            this.KeyProvider = aesBase64Transformer.KeyProvider;
            this.Encoding = encoding ?? Encoding.UTF8;
        }

        protected AesBase64Transformer AesBase64Transformer { get; set; }

        /// <summary>
        /// Gets or sets the function that provides the AES key for decryption.
        /// </summary>
        public Func<AesKey> KeyProvider { get; set; }

        /// <summary>
        /// Gets or sets the text encoding used when converting decrypted bytes to a string.
        /// </summary>
        public Encoding Encoding { get; set; }

        /// <summary>
        /// Gets or sets the HTTP context for context-aware cloning.
        /// </summary>
        public IHttpContext HttpContext { get; set; } = null!;

        /// <summary>
        /// Creates a shallow clone of this instance, copying properties and event handlers.
        /// </summary>
        /// <returns>A new cloned instance.</returns>
        public object Clone()
        {
            object clone = new AesBase64ReverseTransformer(this.AesBase64Transformer, Encoding);
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
            AesBase64ReverseTransformer clone = new AesBase64ReverseTransformer(this.AesBase64Transformer, Encoding);
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
        /// Decrypts a Base64-encoded AES cipher string back to plain text.
        /// </summary>
        /// <param name="base64EncodedCipher">The Base64-encoded cipher text to decrypt.</param>
        /// <returns>The decrypted plain text string.</returns>
        public string ReverseTransform(string base64EncodedCipher)
        {
            AesKey aesKey = KeyProvider();
            byte[] cipherBytes = Convert.FromBase64String(base64EncodedCipher);
            byte[] decipheredBytes = aesKey.DecryptBytes(cipherBytes);

            return Encoding.GetString(decipheredBytes);
        }

        /// <summary>
        /// Gets the forward transformer (encryptor) associated with this reverse transformer.
        /// </summary>
        /// <returns>The <see cref="AesBase64Transformer"/> used for encryption.</returns>
        public IValueTransformer<string, string> GetTransformer()
        {
            return this.AesBase64Transformer;
        }
    }
}

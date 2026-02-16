//using Bam.Server.ServiceProxy;

using System.Text;

namespace Bam.Encryption
{
    /// <summary>
    /// Value transformer that encrypts and decrypts strings as Base64-encoded RSA ciphers.
    /// </summary>
    public class RsaBase64Transformer : ValueTransformer<string, string>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaBase64Transformer"/> class with the specified key provider function.
        /// </summary>
        /// <param name="keyProvider">A function that provides the RSA key pair.</param>
        public RsaBase64Transformer(Func<RsaPublicPrivateKeyPair> keyProvider)
        {
            this.Encoding = Encoding.UTF8;
            this.KeyProvider = keyProvider;
            this.RsaBase64ReverseTransformer = new RsaBase64ReverseTransformer(this);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaBase64Transformer"/> class with the specified RSA key source.
        /// </summary>
        /// <param name="rsaKeySource">The source that provides the RSA key pair.</param>
        public RsaBase64Transformer(IRsaKeySource rsaKeySource) : this(() => rsaKeySource.GetRsaKey())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaBase64Transformer"/> class with the specified RSA key pair.
        /// </summary>
        /// <param name="rsaPublicPrivateKeyPair">The RSA key pair to use for encryption.</param>
        public RsaBase64Transformer(RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair) : this(() => rsaPublicPrivateKeyPair)
        { 
        }

        /// <summary>
        /// Gets or sets the paired reverse RSA Base64 transformer.
        /// </summary>
        protected RsaBase64ReverseTransformer RsaBase64ReverseTransformer { get; set; }

        /// <summary>
        /// Gets or sets the character encoding to use for string conversion.
        /// </summary>
        public Encoding Encoding { get; set; }

        /// <summary>
        /// Gets or sets the function that provides the RSA key pair.
        /// </summary>
        public Func<RsaPublicPrivateKeyPair> KeyProvider { get; set; }

        /// <summary>
        /// Converts the specified base 64 encoded cipher to plain text.
        /// </summary>
        /// <param name="base64Cipher"></param>
        /// <returns></returns>
        public override string ReverseTransform(string base64Cipher)
        {
            return GetReverseTransformer().ReverseTransform(base64Cipher);
        }

        /// <summary>
        /// Gets a base64 encoded cipher for the specified plain text.
        /// </summary>
        /// <param name="plainText"></param>
        /// <returns></returns>
        public override string Transform(string plainText)
        {
            RsaPublicPrivateKeyPair rsaKey = KeyProvider();
            return rsaKey.Encrypt(plainText, Encoding);
        }

        /// <inheritdoc />
        public override IValueReverseTransformer<string, string> GetReverseTransformer()
        {
            return this.RsaBase64ReverseTransformer;
        }
    }
}

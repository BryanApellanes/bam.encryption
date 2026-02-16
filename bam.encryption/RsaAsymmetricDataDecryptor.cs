using System.Text;

namespace Bam.Encryption
{
    /// <summary>
    /// Decrypts typed data using RSA asymmetric decryption as a reverse transformer pipeline.
    /// </summary>
    /// <typeparam name="TData">The type of data to decrypt.</typeparam>
    public class RsaAsymmetricDataDecryptor<TData> : ValueReverseTransformerPipeline<TData>, IDecryptor<TData>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAsymmetricDataDecryptor{TData}"/> class from the specified encryptor.
        /// </summary>
        /// <param name="encryptor">The encryptor whose transformers will be reversed for decryption.</param>
        public RsaAsymmetricDataDecryptor(RsaAsymmetricDataEncryptor<TData> encryptor) : base(encryptor)
        {
            this.Encryptor = encryptor;
        }

        protected RsaAsymmetricDataEncryptor<TData> Encryptor { get; private set; }

        /// <inheritdoc />
        public TData DecryptCipher(Cipher<TData> cipherData)
        {
            return ReverseTransform(cipherData);
        }

        /// <inheritdoc />
        public string DecryptCipher(Cipher cipher)
        {
            return Decrypt(cipher.ToString());
        }

        /// <inheritdoc />
        public string Decrypt(string cipher)
        {
            byte[] cipherData = Convert.FromBase64String(cipher);
            byte[] utf8 = this.Encryptor.RsaByteTransformer.ReverseTransform(cipherData);

            return Encoding.UTF8.GetString(utf8); 
        }

        /// <inheritdoc />
        public byte[] Decrypt(byte[] cipher)
        {
            return Encryptor.RsaByteTransformer.ReverseTransform(cipher);
        }
    }
}

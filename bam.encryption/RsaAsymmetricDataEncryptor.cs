using System.Text;

namespace Bam.Encryption
{
    /// <summary>
    /// Encrypts typed data using RSA asymmetric encryption as a value transformer pipeline.
    /// </summary>
    /// <typeparam name="TData">The type of data to encrypt.</typeparam>
    public class RsaAsymmetricDataEncryptor<TData> : ValueTransformerPipeline<TData>, IEncryptor<TData>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAsymmetricDataEncryptor{TData}"/> class with the specified RSA public key source.
        /// </summary>
        /// <param name="rsaPublicKeySource">The source of the RSA public key for encryption.</param>
        public RsaAsymmetricDataEncryptor(IRsaPublicKeySource rsaPublicKeySource)
        {
            this.RsaByteTransformer = new RsaByteTransformer(rsaPublicKeySource);

            this.Add(this.RsaByteTransformer);
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAsymmetricDataEncryptor{TData}"/> class with the specified RSA key pair.
        /// </summary>
        /// <param name="rsaPublicPrivateKeyPair">The RSA key pair whose public key is used for encryption.</param>
        public RsaAsymmetricDataEncryptor(RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair)
        {
            this.RsaByteTransformer = new RsaByteTransformer(rsaPublicPrivateKeyPair);

            this.Add(this.RsaByteTransformer);
        }

        protected internal RsaByteTransformer RsaByteTransformer { get; private set; }

        /// <summary>
        /// Gets a reverse transformer that can decrypt data encrypted by this encryptor.
        /// </summary>
        /// <returns>A new RSA asymmetric data decryptor.</returns>
        public new RsaAsymmetricDataDecryptor<TData> GetReverseTransformer()
        {
            return new RsaAsymmetricDataDecryptor<TData>(this);
        }

        /// <summary>
        /// Encrypts and gzips the json representation of the specified data.
        /// </summary>
        /// <param name="data">The object data to encrypt.</param>
        /// <returns>byte[]</returns>
        public virtual Cipher<TData> Encrypt(TData data)
        {
            return Transform(data);
        }

        /// <inheritdoc />
        public IDecryptor<TData> GetDecryptor()
        {
            return GetReverseTransformer();
        }

        /// <inheritdoc />
        IDecryptor IEncryptor.GetDecryptor()
        {
            return GetDecryptor();
        }

        /// <summary>
        /// Encrypts the specified string and returns the base 64 encoded cipher.
        /// </summary>
        /// <param name="plainData"></param>
        /// <returns></returns>
        public string Encrypt(string plainData)
        {
            byte[] utf8 = Encoding.UTF8.GetBytes(plainData);
            byte[] cipherData = RsaByteTransformer.Transform(utf8);

            return cipherData.ToBase64();
        }

        /// <inheritdoc />
        public byte[] Encrypt(byte[] plainData)
        {
            return RsaByteTransformer.Transform(plainData);
        }
    }
}

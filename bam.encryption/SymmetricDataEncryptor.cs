using System.Text;
using Bam.Storage;

namespace Bam.Encryption
{
    /// <summary>
    /// Encrypts typed data using AES symmetric encryption as a value transformer pipeline.
    /// </summary>
    /// <typeparam name="TData">The type of data to encrypt.</typeparam>
    public class SymmetricDataEncryptor<TData> : ValueTransformerPipeline<TData>, IEncryptor<TData>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricDataEncryptor{TData}"/> class with the specified AES key source factory.
        /// </summary>
        /// <param name="aesKeySource">A function that provides the AES key source.</param>
        public SymmetricDataEncryptor(Func<IAesKeySource> aesKeySource) : this(aesKeySource())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricDataEncryptor{TData}"/> class with the specified AES key source.
        /// </summary>
        /// <param name="aesKeySource">The source of the AES key for encryption.</param>
        public SymmetricDataEncryptor(IAesKeySource aesKeySource)
        {
            this.AesByteTransformer = new AesByteTransformer(aesKeySource);

            this.Add(this.AesByteTransformer);
        }

        protected internal AesByteTransformer AesByteTransformer { get; private set; }

        /// <summary>
        /// Gets a reverse transformer that can decrypt data encrypted by this encryptor.
        /// </summary>
        /// <returns>A new symmetric data decryptor.</returns>
        public new SymmetricDataDecryptor<TData> GetReverseTransformer()
        {
            return new SymmetricDataDecryptor<TData>(this);
        }

        /// <summary>
        /// Encrypts the json representation of the specified data.
        /// </summary>
        /// <param name="data">The object data to encrypt.</param>
        /// <returns>byte[]</returns>
        public virtual Cipher<TData> Encrypt(TData data)
        {
            Cipher<TData> cipher = new Cipher<TData>
            {
                Data = Transform(data)
            };
            return cipher;
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
        /// Encrypt the specified string
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The base64 encoded cipher.</returns>
        public string Encrypt(string plainData)
        {
            byte[] utf8 = Encoding.UTF8.GetBytes(plainData);
            byte[] cipherData = AesByteTransformer.Transform(utf8);

            return cipherData.ToBase64();
        }

        /// <summary>
        /// Encrypt the specified data.
        /// </summary>
        /// <param name="plainData">The data to encrypt.</param>
        /// <returns>The cipher.</returns>
        public byte[] Encrypt(byte[] plainData)
        {
            return AesByteTransformer.Transform(plainData);
        }
    }
}

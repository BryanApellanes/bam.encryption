using System.Text;

namespace Bam.Encryption
{
    public class RsaAsymmetricDataEncryptor<TData> : ValueTransformerPipeline<TData>, IEncryptor<TData>
    {
        public RsaAsymmetricDataEncryptor(IRsaPublicKeySource rsaPublicKeySource)
        {
            this.RsaByteTransformer = new RsaByteTransformer(rsaPublicKeySource);

            this.Add(this.RsaByteTransformer);
        }

        public RsaAsymmetricDataEncryptor(RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair)
        {
            this.RsaByteTransformer = new RsaByteTransformer(rsaPublicPrivateKeyPair);

            this.Add(this.RsaByteTransformer);
        }

        protected internal RsaByteTransformer RsaByteTransformer { get; private set; }

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

        public IDecryptor<TData> GetDecryptor()
        {
            return GetReverseTransformer();
        }

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

        public byte[] Encrypt(byte[] plainData)
        {
            return RsaByteTransformer.Transform(plainData);
        }
    }
}

using System.Text;

namespace Bam.Encryption
{
    public class RsaAsymmetricDataDecryptor<TData> : ValueReverseTransformerPipeline<TData>, IDecryptor<TData>
    {
        public RsaAsymmetricDataDecryptor(RsaAsymmetricDataEncryptor<TData> encryptor) : base(encryptor)
        {
            this.Encryptor = encryptor;
        }

        protected RsaAsymmetricDataEncryptor<TData> Encryptor { get; private set; }

        public TData DecryptCipher(Cipher<TData> cipherData)
        {
            return ReverseTransform(cipherData);
        }

        public string DecryptCipher(Cipher cipher)
        {
            return Decrypt(cipher.ToString());
        }

        public string Decrypt(string cipher)
        {
            byte[] cipherData = Convert.FromBase64String(cipher);
            byte[] utf8 = this.Encryptor.RsaByteTransformer.ReverseTransform(cipherData);

            return Encoding.UTF8.GetString(utf8); 
        }

        public byte[] Decrypt(byte[] cipher)
        {
            return Encryptor.RsaByteTransformer.ReverseTransform(cipher);
        }
    }
}

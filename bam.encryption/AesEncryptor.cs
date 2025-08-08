namespace Bam.Encryption
{
    public class AesEncryptor : IEncryptor
    {
        public AesEncryptor(IAesKeySource keySource)
        {
            this.KeyProvider = () => keySource.GetAesKey();
        }
        public AesEncryptor(Func<AesKey> keyProvider)
        {
            this.KeyProvider = keyProvider;
        }

        public AesEncryptor(AesKey aesKey)
        {
            this.KeyProvider = () => aesKey;
        }

        public Func<AesKey> KeyProvider { get; set; }

        public IDecryptor GetDecryptor()
        {
            return new AesDecryptor(this.KeyProvider);
        }

        public string Encrypt(string plainData)
        {
            AesKey aesKey = KeyProvider();
            return aesKey.Encrypt(plainData);
        }

        public byte[] Encrypt(byte[] plainData)
        {
            AesKey aesKey = KeyProvider();
            return aesKey.EncryptBytes(plainData);            
        }
    }
}

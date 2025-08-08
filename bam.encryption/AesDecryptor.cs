namespace Bam.Encryption
{
    public class AesDecryptor : IDecryptor
    {
        public AesDecryptor(IAesKeySource aesKeySource)
        {
            this.KeyProvider = () => aesKeySource.GetAesKey();
        }

        public AesDecryptor(Func<AesKey> keyProvider)
        {
            this.KeyProvider = keyProvider;
        }

        public AesDecryptor(AesKey aesKey)
        {
            this.KeyProvider = () => aesKey;
        }

        public Func<AesKey> KeyProvider { get; set; }

        public string DecryptCipher(Cipher cipher)
        {
            return Decrypt(cipher.ToString());
        }

        public string Decrypt(string cipher)
        {
            AesKey aesKey = KeyProvider();
            return aesKey.Decrypt(cipher);
        }

        public byte[] Decrypt(byte[] cipher)
        {
            AesKey aesKey = KeyProvider();
            return aesKey.DecryptBytes(cipher);
        }
    }
}

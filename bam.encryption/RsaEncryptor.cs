namespace Bam.Encryption
{
    public class RsaEncryptor : IEncryptor
    {
        public RsaEncryptor(IRsaKeySource rsaKeySource)
        {
            this.KeyProvider = () => rsaKeySource.GetRsaKey();
        }

        public RsaEncryptor(Func<RsaPublicPrivateKeyPair> keyProvider)
        {
            this.KeyProvider = keyProvider;
        }

        public RsaEncryptor(RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair)
        {
            this.KeyProvider = () => rsaPublicPrivateKeyPair;
        }

        public Func<RsaPublicPrivateKeyPair> KeyProvider { get; set; }
        public IDecryptor GetDecryptor()
        {
            return new RsaDecryptor(this.KeyProvider);
        }

        public string Encrypt(string plainData)
        {
            RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair = KeyProvider();            
            return rsaPublicPrivateKeyPair.Encrypt(plainData);
        }

        public byte[] Encrypt(byte[] plainData)
        {
            RsaPublicPrivateKeyPair rsaPublicPrivateKeyPair = KeyProvider();
            return rsaPublicPrivateKeyPair.EncryptBytes(plainData);
        }
    }
}

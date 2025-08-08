namespace Bam.Encryption
{
    public class RsaAsymmetricContentEncryptor<TContent> : RsaAsymmetricDataEncryptor<TContent>, IContentEncryptor<TContent>
    {
        public RsaAsymmetricContentEncryptor(IRsaPublicKeySource rsaPublicKeySource) : base(rsaPublicKeySource)
        {
        }

        public ContentCipher<TContent> GetContentCipher(TContent content)
        {
            return new AsymmetricContentCipher<TContent>(Encrypt(content));
        }
    }
}

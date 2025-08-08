namespace Bam.Encryption
{
    public class SymmetricContentDecryptor<TContent> : SymmetricDataDecryptor<TContent>, IContentDecryptor<TContent>
    {
        public SymmetricContentDecryptor(IAesKeySource aesKeysource) : base(new SymmetricDataEncryptor<TContent>(aesKeysource))
        {
        }

        public TContent DecryptContentCipher(ContentCipher<TContent> contentCipher)
        {
            return DecryptCipher((Cipher<TContent>)contentCipher);
        }
    }
}

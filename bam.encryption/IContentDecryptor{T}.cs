namespace Bam.Encryption
{
    public interface IContentDecryptor<TContent> : IDecryptor<TContent>
    {
        TContent DecryptContentCipher(ContentCipher<TContent> contentCipher);
    }
}

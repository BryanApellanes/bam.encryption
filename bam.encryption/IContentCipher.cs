namespace Bam.Encryption
{
    public interface IContentCipher
    {
        byte[] Data { get; }
        string ContentType { get; }
    }
}

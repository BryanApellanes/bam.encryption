namespace Bam.Encryption
{
    public interface ISaltProvider
    {
        int SaltLength { get; set; }
        string GetSalt();
    }
}

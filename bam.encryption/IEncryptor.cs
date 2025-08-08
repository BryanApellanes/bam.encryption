namespace Bam.Encryption
{
    public interface IEncryptor<TData> : IEncryptor
    {
        Cipher<TData> Encrypt(TData data);

        IDecryptor<TData> GetDecryptor();
    }

    public interface IEncryptor
    {
        IDecryptor GetDecryptor();
        string Encrypt(string plainData);
        byte[] Encrypt(byte[] plainData);
    }
}

namespace Bam.Encryption
{
    public interface IDecryptor<TData> : IDecryptor
    {
        TData DecryptCipher(Cipher<TData> cipherData);
    }

    public interface IDecryptor
    {
        string DecryptCipher(Cipher cipher);
        string Decrypt(string cipher);
        byte[] Decrypt(byte[] cipher);
    }
}

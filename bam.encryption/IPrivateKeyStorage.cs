namespace Bam.Encryption;

public interface IPrivateKeyStorage
{
    string Store(string pemString);
    string Store(string pemString, HashAlgorithms algorithm);
    string Retrieve(string hash);
    string Retrieve(string hash, HashAlgorithms algorithm);
    bool Delete(string hash);
}
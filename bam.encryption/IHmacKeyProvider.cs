namespace Bam.Encryption;

public interface IHmacKeyProvider
{
    byte[] GetNewHmacKey();
    byte[] GetNamedHmacKey(string name);
}
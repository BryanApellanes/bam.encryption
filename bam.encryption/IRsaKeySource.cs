namespace Bam.Encryption
{
    public interface IRsaKeySource : IRsaPublicKeySource
    {
        RsaPublicPrivateKeyPair GetRsaKey();
    }
}

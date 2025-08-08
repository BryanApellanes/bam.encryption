namespace Bam.Encryption
{
    public class RsaAsymmetricContentCipher : ContentCipher
    {
        public RsaAsymmetricContentCipher(byte[] data)
        {
            this.Data = data;
            this.ContentType = MediaTypes.AsymmetricCipher;
        }
    }
}

namespace Bam.Encryption
{
    public class AsymmetricContentCipher<TContent> : ContentCipher<TContent>
    {
        public AsymmetricContentCipher(byte[] data)
        {
            this.Data = data;
            this.ContentType = MediaTypes.AsymmetricCipher;
        }
    }
}

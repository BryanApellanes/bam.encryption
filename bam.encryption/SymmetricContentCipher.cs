namespace Bam.Encryption
{
    public class SymmetricContentCipher : ContentCipher
    {
        public SymmetricContentCipher(byte[] data)
        {
            this.Data = data;
            this.ContentType = MediaTypes.SymmetricCipher;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public class AsymmetricContentEncryptor<TContent> : AsymmetricDataEncryptor<TContent>, IContentEncryptor<TContent>
    {
        public AsymmetricContentEncryptor(IRsaPublicKeySource rsaPublicKeySource) : base(rsaPublicKeySource)
        {
        }

        public ContentCipher<TContent> GetContentCipher(TContent content)
        {
            return new AsymmetricContentCipher<TContent>(Encrypt(content));
        }
    }
}

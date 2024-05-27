using Bam.Encryption;
using Bam.Server;
using Bam.ServiceProxy.Encryption;
using System;
using System.Collections.Generic;
using System.Text;

namespace Bam.Encryption
{
    public class SymmetricEncryptedHttpResponse<T> : EncryptedHttpResponse
    {
        public SymmetricEncryptedHttpResponse()
        {
            this.StatusCode = 200;
        }

        public SymmetricEncryptedHttpResponse(T data, IAesKeySource aesKeySource) : this()
        {
            SymmetricDataEncryptor<T> encryptor = new SymmetricDataEncryptor<T>(aesKeySource);
            this.ContentCipher = new SymmetricContentCipher(encryptor.Encrypt(data));
        }
    }
}

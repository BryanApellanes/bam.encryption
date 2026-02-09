/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.Encryption
{
    public class Decrypted: Encrypted
    {
        public Decrypted(byte[] cipher, byte[] key, byte[] iv)
            : base(cipher, key, iv)
        {
        }

        public Decrypted(Encrypted value)
            : base(value.Cipher, value.Key, value.IV)
        {
            this.SaltLength = value.SaltLength;
            Decrypt();
        }

        public Decrypted(string base64Cipher, AesKey aesKey) 
            : this(base64Cipher.FromBase64(), aesKey.Key, aesKey.IV)
        { 
        }

        public static implicit operator string(Decrypted dec)
        {
            return dec.Value;
        }

        public override string Value
        {
            get
            {
                if (string.IsNullOrEmpty(Plain))
                {
                    Decrypt();
                }

                return Plain;
            }
        }

        protected string Decrypt()
        {
            Plain = Decrypt(Cipher, Key, IV).Truncate(SaltLength);
            return Plain;
        }

        public static string Decrypt(byte[] cipher, byte[] key, byte[] iv)
        {
            return Aes.Decrypt(cipher, key, iv);
        }
    }
}

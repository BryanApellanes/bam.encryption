/*
	Copyright © Bryan Apellanes 2015  
*/

using Org.BouncyCastle.Security;

namespace Bam.Encryption
{
    /// <summary>
    /// A salted encryption cipher.
    /// </summary>
    public class Encrypted : DisposableAesKey
    {
        protected static readonly int DefaultSaltLength = 8;

        public Encrypted()
        {
            this.SaltLength = DefaultSaltLength;
            SecureRandom random = new SecureRandom();
            this.Key = random.GenerateSeed(16);
            this.IV = random.GenerateSeed(16);
            this.Plain = string.Empty;
        }

        public Encrypted(string plainText): this()
        {
            this.Plain = plainText;
        }

        public Encrypted(string plainText, AesKey key)//: this(plainText, key.Key, key.IV)
        {
            this.Plain = plainText;
            this.Key = key.Key;
            this.IV = key.IV;
            this.Cipher = Encrypt();
        }
        

        protected Encrypted(byte[] cipher, byte[] key, byte[] iv) : this()
        {
            this.Key = key;
            this.Cipher = cipher;
            this.IV = iv;
        }

        public static implicit operator string(Encrypted enc)
        {
            return enc.Value;
        }

        public virtual string Value => Base64Cipher;

        public int SaltLength
        {
            get;
            set;
        }

        public string Plain
        {
            get;
            set;
        }

        public byte[] Cipher
        {
            get;
            private set;
        }

        public string Base64Cipher
        {
            get
            {
                if (Cipher == null)
                {
                    Encrypt();
                }

                return Convert.ToBase64String(Cipher);
            }
            protected set => Cipher = Convert.FromBase64String(value);
        }

        /// <summary>
        /// Gets the base64 encoded key.
        /// </summary>
        protected string Base64Key
        {
            get => Key != null ? Convert.ToBase64String(Key) : string.Empty;
            set => Key = Convert.FromBase64String(value);
        }

        /// <summary>
        /// Gets the base64 encoded initialization vector.
        /// </summary>
        protected string Base64IV
        {
            get => IV != null ? Convert.ToBase64String(IV) : string.Empty;
            set
            {
                IV = Convert.FromBase64String(value);
            }
        }

        private byte[] Encrypt()
        {
            Base64Cipher = Aes.Encrypt(string.Concat(Plain, SaltLength.SecureAlphaNumericCharacters()), Base64Key, Base64IV);
            return Cipher;
        }
    }
}

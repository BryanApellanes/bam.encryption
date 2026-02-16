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

        /// <summary>
        /// Initializes a new instance of the <see cref="Encrypted"/> class with a randomly generated AES key and IV.
        /// </summary>
        public Encrypted()
        {
            this.SaltLength = DefaultSaltLength;
            SecureRandom random = new SecureRandom();
            this.Key = random.GenerateSeed(16);
            this.IV = random.GenerateSeed(16);
            this.Plain = string.Empty;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Encrypted"/> class with the specified plain text, generating a random AES key and IV.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        public Encrypted(string plainText): this()
        {
            this.Plain = plainText;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Encrypted"/> class, encrypting the specified plain text using the given AES key.
        /// </summary>
        /// <param name="plainText">The plain text to encrypt.</param>
        /// <param name="key">The AES key to use for encryption.</param>
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

        /// <summary>
        /// Gets the Base64-encoded cipher text.
        /// </summary>
        public virtual string Value => Base64Cipher;

        /// <summary>
        /// Gets or sets the number of random salt characters appended to the plain text before encryption.
        /// </summary>
        public int SaltLength
        {
            get;
            set;
        }

        /// <summary>
        /// Gets or sets the plain text value before encryption.
        /// </summary>
        public string Plain
        {
            get;
            set;
        }

        /// <summary>
        /// Gets the encrypted cipher as a byte array.
        /// </summary>
        public byte[] Cipher
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets or sets the cipher as a Base64-encoded string. Performs lazy encryption on first access if not yet encrypted.
        /// </summary>
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

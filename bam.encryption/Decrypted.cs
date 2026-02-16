/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.Encryption
{
    /// <summary>
    /// Represents the decrypted form of an <see cref="Encrypted"/> value, automatically decrypting upon construction from an Encrypted instance.
    /// </summary>
    public class Decrypted: Encrypted
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Decrypted"/> class with the specified cipher, key, and IV bytes.
        /// </summary>
        /// <param name="cipher">The encrypted cipher bytes.</param>
        /// <param name="key">The AES key bytes.</param>
        /// <param name="iv">The initialization vector bytes.</param>
        public Decrypted(byte[] cipher, byte[] key, byte[] iv)
            : base(cipher, key, iv)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Decrypted"/> class from an <see cref="Encrypted"/> instance, immediately performing decryption.
        /// </summary>
        /// <param name="value">The encrypted value to decrypt.</param>
        public Decrypted(Encrypted value)
            : base(value.Cipher, value.Key, value.IV)
        {
            this.SaltLength = value.SaltLength;
            Decrypt();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Decrypted"/> class from a Base64-encoded cipher and an AES key.
        /// </summary>
        /// <param name="base64Cipher">The Base64-encoded cipher text.</param>
        /// <param name="aesKey">The AES key to use for decryption.</param>
        public Decrypted(string base64Cipher, AesKey aesKey)
            : this(base64Cipher.FromBase64(), aesKey.Key, aesKey.IV)
        {
        }

        public static implicit operator string(Decrypted dec)
        {
            return dec.Value;
        }

        /// <summary>
        /// Gets the decrypted plain text value, performing lazy decryption if not yet decrypted.
        /// </summary>
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

        /// <summary>
        /// Decrypts the specified cipher byte array using the provided key and IV.
        /// </summary>
        /// <param name="cipher">The encrypted byte array.</param>
        /// <param name="key">The AES key bytes.</param>
        /// <param name="iv">The initialization vector bytes.</param>
        /// <returns>The decrypted plain text string.</returns>
        public static string Decrypt(byte[] cipher, byte[] key, byte[] iv)
        {
            return Aes.Decrypt(cipher, key, iv);
        }
    }
}

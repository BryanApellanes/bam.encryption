/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.Encryption
{
    /// <summary>
    /// Represents a class that encrypts data with a provided password.
    /// </summary>
    public class PasswordEncrypted
    {
        protected PasswordEncrypted() { }

        /// <summary>
        /// Create a PasswordEncrypted instance.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password used to encrypt the data.</param>
        public PasswordEncrypted(string data, string password)
        {
            this.Data = data;
            this.Encrypt(password);
        }

        /// <summary>
        /// Implicitly converts a <see cref="PasswordEncrypted"/> to its cipher text string.
        /// </summary>
        /// <param name="p">The password-encrypted instance.</param>
        public static implicit operator string(PasswordEncrypted p)
        {
            return p.Cipher;
        }

        /// <summary>
        /// Gets the current value, which is the cipher text for this class.
        /// </summary>
        public virtual string Value => Cipher;

        /// <summary>
        /// Gets the original plain text data.
        /// </summary>
        public string Data
        {
            get;
            protected set;
        }

        /// <summary>
        /// Gets the encrypted cipher text.
        /// </summary>
        public string Cipher
        {
            get;
            internal set;
        }

        string _password;
        protected internal string Password
        {
            get => _password;
            set => Encrypt(value);
        }

        /// <summary>
        /// Encrypts the data using the specified password and returns the cipher text.
        /// </summary>
        /// <param name="password">The password to use for encryption.</param>
        /// <returns>The encrypted cipher text.</returns>
        public string Encrypt(string password)
        {
            _password = password;
            Cipher = Rijndael.EncryptStringAES(Data, password);
            return Cipher;
        }
    }

}

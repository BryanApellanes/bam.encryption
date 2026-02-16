/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.Encryption
{
    /// <summary>
    /// Represents a password-decrypted value that can decrypt cipher text using Rijndael encryption.
    /// </summary>
    public class PasswordDecrypted: PasswordEncrypted
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordDecrypted"/> class from an encrypted instance and password.
        /// </summary>
        /// <param name="encrypted">The password-encrypted instance containing the data.</param>
        /// <param name="password">The password used for encryption/decryption.</param>
        public PasswordDecrypted(PasswordEncrypted encrypted, string password)
            : base(encrypted.Data, password)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordDecrypted"/> class by decrypting the specified cipher text.
        /// </summary>
        /// <param name="cipher">The Base64-encoded cipher text to decrypt.</param>
        /// <param name="password">The password used for decryption.</param>
        public PasswordDecrypted(string cipher, string password)
        {
            Cipher = cipher;
            Data = Decrypt(password);
        }

        /// <summary>
        /// Implicitly converts a <see cref="PasswordDecrypted"/> to its decrypted string value.
        /// </summary>
        /// <param name="d">The password-decrypted instance.</param>
        public static implicit operator string(PasswordDecrypted d)
        {
            return d.Data;
        }

        /// <inheritdoc />
        public override string Value => Data;

        /// <summary>
        /// Decrypts the cipher text using the specified password.
        /// </summary>
        /// <param name="password">The password to use for decryption.</param>
        /// <returns>The decrypted plain text.</returns>
        public string Decrypt(string password)
        {
            string result = string.Empty; 
            if (!string.IsNullOrEmpty(Data))
            {
                result = Data;// no need to decrypt if Data was already set by ctor
            }
            else if(!string.IsNullOrEmpty(Cipher))
            {
                result = Rijndael.DecryptStringAES(Cipher, password);
                Data = result;
            }
            else
            {
                throw new InvalidOperationException("Data and Cipher were both null or empty");
            }

            return result;
        }
    }
}

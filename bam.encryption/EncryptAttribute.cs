/*
	Copyright © Bryan Apellanes 2015  
*/

namespace Bam.Encryption
{
    /// <summary>
    /// Denotes a class that requires encryption when streamed to file
    /// or network.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class)]
    public class EncryptAttribute : Attribute
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptAttribute"/> class with the default symmetric encryption scheme.
        /// </summary>
        public EncryptAttribute()
        {
            this.EncryptionScheme = EncryptionSchemes.Symmetric;
        }

        /// <summary>
        /// Gets or sets the encryption scheme to use. Defaults to <see cref="EncryptionSchemes.Symmetric"/>.
        /// </summary>
        public EncryptionSchemes EncryptionScheme { get; set; }
    }
}

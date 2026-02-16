namespace Bam.Encryption
{
    /// <summary>
    /// Defines the available encryption schemes.
    /// </summary>
    public enum EncryptionSchemes
    {
        /// <summary>
        /// Indicates an invalid or unspecified encryption scheme.
        /// </summary>
        Invalid,

        /// <summary>
        /// Symmetric encryption (e.g., AES) where the same key is used for encryption and decryption.
        /// </summary>
        Symmetric,

        /// <summary>
        /// Asymmetric encryption (e.g., RSA) where different keys are used for encryption and decryption.
        /// </summary>
        Asymmetric
    }
}

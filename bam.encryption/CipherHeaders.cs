using Bam.Web;

namespace Bam.Encryption
{
    /// <summary>
    /// Defines HTTP header names for public-key encrypted header values used in service proxy communication.
    /// </summary>
    public static class CipherHeaders
    {
        /// <summary>
        /// Public key cipher of the ProcessLocalIdentifier.
        /// </summary>
        public static string ProcessLocalIdentifierCipher => $"{Headers.ProcessLocalIdentifier}-Cipher";

        /// <summary>
        /// Public key cipher of the ProcessDescriptor.
        /// </summary>
        public static string ProcessDescriptorCipher => $"{Headers.ProcessDescriptor}-Cipher";

        /// <summary>
        /// Public key cipher of the ProcessMode.
        /// </summary>
        public static string ProcessModeCipher => $"{Headers.ProcessMode}-Cipher";

        /// <summary>
        /// Public key cipher of the ApplicationName.
        /// </summary>
        public static string ApplicationNameCipher => $"{Headers.ApplicationName}-Cipher";

        /// <summary>
        /// Holds the public key encrypted hash of the unencrypted request body.
        /// </summary>
        public static string HashCipher => $"{Headers.Hash}-Cipher";

        /// <summary>
        /// Public key cipher of the timestamp.
        /// </summary>
        public static string TimestampCipher => "X-Bam-Timestamp-Cipher";
    }
}

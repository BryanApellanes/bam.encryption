namespace Bam.Encryption
{
    /// <summary>
    /// Defines a provider that generates cryptographic salt values.
    /// </summary>
    public interface ISaltProvider
    {
        /// <summary>
        /// Gets or sets the length of the salt to generate.
        /// </summary>
        int SaltLength { get; set; }

        /// <summary>
        /// Generates and returns a new salt string.
        /// </summary>
        /// <returns>The generated salt string.</returns>
        string GetSalt();
    }
}

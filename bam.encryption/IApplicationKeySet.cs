namespace Bam.Encryption
{
    /// <summary>
    /// Defines a key set associated with a specific application.
    /// </summary>
    public interface IApplicationKeySet
    {
        /// <summary>
        /// Gets or sets the application name.
        /// </summary>
        string ApplicationName { get; set; }
    }
}

namespace Bam.Encryption
{
    /// <summary>
    /// Defines a key set used for server-client communication, identified by server and client hostnames.
    /// </summary>
    public interface ICommunicationKeySet
    {
        /// <summary>
        /// Gets or sets the server host name.
        /// </summary>
        string ServerHostName { get; set; }

        /// <summary>
        /// Gets or sets the client host name.
        /// </summary>
        string ClientHostName { get; set; }
    }
}

using Bam.Configuration;

namespace Bam.Encryption
{
    /// <summary>
    /// Provides a cryptographic salt value read from the application configuration, falling back to random letters if the configuration key is not found.
    /// </summary>
    public class DefaultConfigurationSaltProvider : ISaltProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultConfigurationSaltProvider"/> class
        /// initializing the salt to the value in the configuration file for the 
        /// specified saltKey
        /// </summary>
        /// <param name="saltKey">The salt key.</param>
        public DefaultConfigurationSaltProvider(string saltKey)
        {
            _salt = DefaultConfiguration.GetAppSetting(saltKey, 6.RandomLetters());            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="DefaultConfigurationSaltProvider"/> class using the default "Salt" configuration key.
        /// </summary>
        public DefaultConfigurationSaltProvider() : this("Salt")
        { }

        static ISaltProvider _instance = null!;
        static object _instanceLock = new object();

        /// <summary>
        /// Gets the singleton instance of the <see cref="DefaultConfigurationSaltProvider"/>, lazily initialized with the default "Salt" key.
        /// </summary>
        public static ISaltProvider Instance
        {
            get
            {
                return _instanceLock.DoubleCheckLock(ref _instance, () => new DefaultConfigurationSaltProvider());
            }
        }

        /// <summary>
        /// Gets the length of the salt string. Setting this value throws an <see cref="InvalidOperationException"/> because the salt is sourced from configuration.
        /// </summary>
        public int SaltLength
        {
            get { return _salt.Length; }
            set { throw new InvalidOperationException("This SaltProvider uses salt from the configuration file and cannot set the length directly."); }
        }

        string _salt;

        /// <summary>
        /// Gets the salt string loaded from the application configuration.
        /// </summary>
        /// <returns>The salt string.</returns>
        public string GetSalt()
        {
            return _salt;
        }
    }
}

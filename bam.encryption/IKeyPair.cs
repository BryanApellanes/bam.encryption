using Bam.Encryption;
using Org.BouncyCastle.Crypto;

namespace Bam.encryption;

/// <summary>
/// Defines a cryptographic key pair containing both public and private keys.
/// </summary>
public interface IKeyPair
{
    /// <summary>
    /// Gets the PEM-encoded public key string.
    /// </summary>
    string PublicPem { get; }

    /// <summary>
    /// Gets the PEM-encoded key pair as a byte array.
    /// </summary>
    byte[] Pem { get; }

    /// <summary>
    /// Gets the public key.
    /// </summary>
    IPublicKey PublicKey { get; }

    /// <summary>
    /// Gets the private key.
    /// </summary>
    IPrivateKey PrivateKey { get; }
}
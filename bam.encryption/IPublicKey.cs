using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

/// <summary>
/// Defines a public key used for asymmetric cryptographic operations.
/// </summary>
public interface IPublicKey
{
    /// <summary>
    /// Gets the PEM-encoded public key string.
    /// </summary>
    string Pem { get; }

    /// <summary>
    /// Gets the underlying asymmetric key parameter value.
    /// </summary>
    AsymmetricKeyParameter Value { get; }
}
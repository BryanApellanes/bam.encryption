using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

/// <summary>
/// Defines a provider that supplies an asymmetric public key parameter.
/// </summary>
public interface IPublicKeyProvider
{
    /// <summary>
    /// Gets the asymmetric public key parameter.
    /// </summary>
    /// <returns>The public key parameter.</returns>
    AsymmetricKeyParameter GetPublicKey();
}
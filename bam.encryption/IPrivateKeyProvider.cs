using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

/// <summary>
/// Defines a provider that supplies an asymmetric private key parameter.
/// </summary>
public interface IPrivateKeyProvider
{
    /// <summary>
    /// Gets the asymmetric private key parameter.
    /// </summary>
    /// <returns>The private key parameter.</returns>
    AsymmetricKeyParameter GetPrivateKey();
}
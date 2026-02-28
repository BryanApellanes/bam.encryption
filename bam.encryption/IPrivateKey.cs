using Org.BouncyCastle.Crypto;

namespace Bam.Encryption;

/// <summary>
/// Defines a private key used for asymmetric cryptographic operations.
/// </summary>
public interface IPrivateKey
{
    /// <summary>
    /// Gets the PEM-encoded private key as a byte array.
    /// </summary>
    byte[] Pem { get; }

    /// <summary>
    /// Gets the underlying asymmetric key parameter value.
    /// </summary>
    AsymmetricKeyParameter Value { get; }

    ISignature Sign(string data);

    ISignature Sign(byte[] data);
}
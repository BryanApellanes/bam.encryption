using Bam.Encryption;

namespace Bam.Encryption;

/// <summary>
/// Defines a provider that creates and verifies digital signatures.
/// </summary>
public interface ISignatureProvider
{
    /// <summary>
    /// Signs the specified data using the private key from the given provider.
    /// </summary>
    /// <param name="privateKeySource">The source of the private key used for signing.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="algorithm">The signing algorithm to use; defaults to SHA512WITHRSA.</param>
    /// <returns>The digital signature.</returns>
    ISignature Sign(IPrivateKeyProvider privateKeySource, string data, string algorithm = "SHA512WITHRSA");

    /// <summary>
    /// Verifies the specified signature against the issuer's public key.
    /// </summary>
    /// <param name="signature">The signature to verify.</param>
    /// <param name="issuerPublicKey">The public key of the signature issuer.</param>
    /// <returns>A verification result indicating whether the signature is valid.</returns>
    ISignatureVerification VerifySignature(ISignature signature, IPublicKey issuerPublicKey);
}
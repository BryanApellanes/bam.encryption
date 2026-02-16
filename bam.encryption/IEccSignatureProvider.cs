namespace Bam.Encryption;

/// <summary>
/// Defines a provider that creates digital signatures using ECC keys.
/// </summary>
public interface IEccSignatureProvider : ISignatureProvider
{
    /// <summary>
    /// Signs the specified data using the ECC key from the given source.
    /// </summary>
    /// <param name="eccKeySource">The source of the ECC key pair used for signing.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="algorithm">The signing algorithm to use, defaults to SHA256WITHECDSA.</param>
    /// <returns>The digital signature.</returns>
    ISignature Sign(IEccKeySource eccKeySource, string data, string algorithm = "SHA256WITHECDSA");
}

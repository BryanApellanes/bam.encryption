namespace Bam.Encryption;

/// <summary>
/// Provides ECC-based digital signature creation using ECDSA.
/// </summary>
public class EccSignatureProvider : SignatureProvider, IEccSignatureProvider
{
    /// <summary>
    /// Signs the specified data using the private key from the given ECC key source.
    /// </summary>
    /// <param name="eccKeySource">The ECC key source providing the private key for signing.</param>
    /// <param name="data">The data to sign.</param>
    /// <param name="algorithm">The signature algorithm to use. Defaults to "SHA256WITHECDSA".</param>
    /// <returns>The digital signature.</returns>
    public ISignature Sign(IEccKeySource eccKeySource, string data, string algorithm = "SHA256WITHECDSA")
    {
        return Sign(new PrivateKeyProvider(eccKeySource.GetEccKey()), data, algorithm);
    }
}

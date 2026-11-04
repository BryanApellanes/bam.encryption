using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Bam.Encryption;

/// <summary>
/// Verifies a detached signature over a binary payload with a BouncyCastle signer
/// (<see cref="SignerUtilities.GetSigner(string)"/>).  The returned
/// <see cref="ISignatureVerification.Signature"/> records the payload as base64 in
/// <see cref="ISignature.Data"/>, since that contract carries text.
/// </summary>
public sealed class DetachedSignatureVerifier : IDetachedSignatureVerifier
{
    /// <inheritdoc />
    public ISignatureVerification Verify(byte[] payload, byte[] signature, IPublicKey signerPublicKey, string algorithm)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(signerPublicKey);
        ArgumentNullException.ThrowIfNull(algorithm);

        Signature record = new Signature
        {
            SignatureBytes = signature,
            Data = Convert.ToBase64String(payload),
            Algorithm = algorithm
        };
        try
        {
            ISigner signer = SignerUtilities.GetSigner(algorithm);
            signer.Init(false, signerPublicKey.Value);
            signer.BlockUpdate(payload, 0, payload.Length);
            bool success = signer.VerifySignature(signature);
            return new SignatureVerification
            {
                Signature = record,
                Success = success,
                Message = success ? string.Empty : "Signature does not verify",
                IssuerPublicKey = signerPublicKey
            };
        }
        catch (Exception e)
        {
            return new SignatureVerification
            {
                Signature = record,
                Success = false,
                Message = e.Message,
                IssuerPublicKey = signerPublicKey
            };
        }
    }
}

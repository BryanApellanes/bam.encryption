namespace Bam.Encryption;

/// <summary>
/// Verifies a detached signature over a binary payload with a named signer algorithm.
/// <see cref="ISignatureProvider.VerifySignature"/> covers signatures over UTF-8 text
/// (<see cref="ISignature.Data"/> is a string); this contract covers payloads that are not text,
/// such as WebAuthn's <c>authenticatorData || SHA-256(clientDataJSON)</c>.
/// </summary>
public interface IDetachedSignatureVerifier
{
    /// <summary>
    /// Verifies that <paramref name="signature"/> is a valid signature over <paramref name="payload"/>
    /// by the private key matching <paramref name="signerPublicKey"/>, using the named algorithm
    /// (a BouncyCastle signer name such as <c>SHA-256withECDSA</c> or <c>SHA-256withRSA</c>).
    /// Never throws for a bad signature, payload or algorithm name: the result's
    /// <see cref="ISignatureVerification.Success"/> is false and <see cref="ISignatureVerification.Message"/>
    /// says why.
    /// </summary>
    /// <param name="payload">The bytes that were signed.</param>
    /// <param name="signature">The signature bytes (DER-encoded for ECDSA).</param>
    /// <param name="signerPublicKey">The public key to verify against.</param>
    /// <param name="algorithm">The signer algorithm name.</param>
    /// <returns>The verification result.</returns>
    ISignatureVerification Verify(byte[] payload, byte[] signature, IPublicKey signerPublicKey, string algorithm);
}

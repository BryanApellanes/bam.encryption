namespace Bam.Encryption.Cose;

/// <summary>
/// COSE signature algorithm identifiers (RFC 9053 / IANA COSE Algorithms) that WebAuthn
/// authenticators commonly offer.
/// </summary>
public enum CoseAlgorithm : long
{
    /// <summary>ECDSA with SHA-256 on P-256.</summary>
    ES256 = -7,
    /// <summary>ECDSA with SHA-384 on P-384.</summary>
    ES384 = -35,
    /// <summary>ECDSA with SHA-512 on P-521.</summary>
    ES512 = -36,
    /// <summary>RSASSA-PKCS1-v1_5 with SHA-256.</summary>
    RS256 = -257
}

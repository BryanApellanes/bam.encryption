namespace Bam.Encryption.Cose;

/// <summary>
/// Facts about the supported <see cref="CoseAlgorithm"/> values: the BouncyCastle signer each
/// maps to (the name <see cref="IDetachedSignatureVerifier"/> and <c>SignerUtilities</c> accept),
/// the named curve an ECDSA algorithm requires, and which COSE key type each belongs to.
/// </summary>
public static class CoseAlgorithms
{
    /// <summary>The COSE key type for elliptic curve keys expressed as x/y coordinates (RFC 9053 §7.1).</summary>
    public const long KeyTypeEc2 = 2;

    /// <summary>The COSE key type for RSA keys (RFC 8230).</summary>
    public const long KeyTypeRsa = 3;

    /// <summary>The COSE curve identifier for P-256 (secp256r1).</summary>
    public const long CurveP256 = 1;

    /// <summary>The COSE curve identifier for P-384 (secp384r1).</summary>
    public const long CurveP384 = 2;

    /// <summary>The COSE curve identifier for P-521 (secp521r1).</summary>
    public const long CurveP521 = 3;

    /// <summary>
    /// Returns whether the COSE algorithm number is one this library supports.
    /// </summary>
    /// <param name="algorithm">The COSE algorithm number.</param>
    public static bool IsSupported(long algorithm)
    {
        return algorithm is (long)CoseAlgorithm.ES256
            or (long)CoseAlgorithm.ES384
            or (long)CoseAlgorithm.ES512
            or (long)CoseAlgorithm.RS256;
    }

    /// <summary>
    /// Gets the BouncyCastle signer name for the algorithm, suitable for
    /// <see cref="IDetachedSignatureVerifier.Verify"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm.</param>
    /// <exception cref="CoseKeyException">The algorithm is not supported.</exception>
    public static string SignerName(CoseAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case CoseAlgorithm.ES256:
                return "SHA-256withECDSA";
            case CoseAlgorithm.ES384:
                return "SHA-384withECDSA";
            case CoseAlgorithm.ES512:
                return "SHA-512withECDSA";
            case CoseAlgorithm.RS256:
                return "SHA-256withRSA";
            default:
                throw new CoseKeyException($"Unsupported COSE algorithm {(long)algorithm}.");
        }
    }

    /// <summary>
    /// Gets the SEC named-curve name for an ECDSA algorithm, or null for RSA algorithms.
    /// </summary>
    /// <param name="algorithm">The algorithm.</param>
    public static string? CurveName(CoseAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case CoseAlgorithm.ES256:
                return "secp256r1";
            case CoseAlgorithm.ES384:
                return "secp384r1";
            case CoseAlgorithm.ES512:
                return "secp521r1";
            default:
                return null;
        }
    }

    /// <summary>
    /// Gets the COSE curve identifier an ECDSA algorithm requires, or null for RSA algorithms.
    /// </summary>
    /// <param name="algorithm">The algorithm.</param>
    public static long? CurveIdentifier(CoseAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case CoseAlgorithm.ES256:
                return CurveP256;
            case CoseAlgorithm.ES384:
                return CurveP384;
            case CoseAlgorithm.ES512:
                return CurveP521;
            default:
                return null;
        }
    }

    /// <summary>
    /// Gets the SEC named-curve name for a COSE curve identifier, or null when unknown.
    /// </summary>
    /// <param name="curve">The COSE curve identifier.</param>
    public static string? CurveNameOf(long curve)
    {
        switch (curve)
        {
            case CurveP256:
                return "secp256r1";
            case CurveP384:
                return "secp384r1";
            case CurveP521:
                return "secp521r1";
            default:
                return null;
        }
    }

    /// <summary>
    /// Gets the COSE key type the algorithm's keys use.
    /// </summary>
    /// <param name="algorithm">The algorithm.</param>
    public static long KeyType(CoseAlgorithm algorithm)
    {
        return algorithm == CoseAlgorithm.RS256 ? KeyTypeRsa : KeyTypeEc2;
    }
}

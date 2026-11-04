using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace Bam.Encryption.Cose;

/// <summary>
/// A parsed COSE_Key (RFC 9052 §7) for one of the <see cref="CoseAlgorithm"/> values, as a
/// WebAuthn authenticator presents its credential public key.  Supports EC2 keys on P-256,
/// P-384 and P-521 (labels <c>crv</c>, <c>x</c>, <c>y</c>) and RSA keys (labels <c>n</c>,
/// <c>e</c>).  <see cref="ToPublicKey"/> converts to the framework's <see cref="EccPublicKey"/>
/// or <see cref="RsaPublicKey"/>, whose canonical PEM is what gets stored and fingerprinted.
/// </summary>
public sealed class CoseKey
{
    private const long LabelKty = 1;
    private const long LabelAlg = 3;
    private const long LabelCrv = -1;
    private const long LabelX = -2;
    private const long LabelY = -3;
    private const long LabelN = -1;
    private const long LabelE = -2;
    private const int MinimumRsaModulusBytes = 256;

    private CoseKey(long keyType, CoseAlgorithm algorithm, long? curve, byte[]? x, byte[]? y, byte[]? modulus, byte[]? exponent)
    {
        KeyType = keyType;
        Algorithm = algorithm;
        Curve = curve;
        X = x;
        Y = y;
        Modulus = modulus;
        Exponent = exponent;
    }

    /// <summary>Gets the COSE key type (<see cref="CoseAlgorithms.KeyTypeEc2"/> or <see cref="CoseAlgorithms.KeyTypeRsa"/>).</summary>
    public long KeyType { get; }

    /// <summary>Gets the algorithm the key is intended for.</summary>
    public CoseAlgorithm Algorithm { get; }

    /// <summary>Gets the COSE curve identifier for an EC2 key, or null for RSA.</summary>
    public long? Curve { get; }

    /// <summary>Gets the x coordinate of an EC2 key, or null for RSA.</summary>
    public byte[]? X { get; }

    /// <summary>Gets the y coordinate of an EC2 key, or null for RSA.</summary>
    public byte[]? Y { get; }

    /// <summary>Gets the RSA modulus, or null for EC2.</summary>
    public byte[]? Modulus { get; }

    /// <summary>Gets the RSA public exponent, or null for EC2.</summary>
    public byte[]? Exponent { get; }

    /// <summary>
    /// Parses an encoded COSE_Key.
    /// </summary>
    /// <param name="encoded">The CBOR-encoded key map.</param>
    /// <returns>The parsed key.</returns>
    /// <exception cref="CoseKeyException">The encoding is not a map, or the key is not supported or is invalid.</exception>
    public static CoseKey Parse(ReadOnlySpan<byte> encoded)
    {
        CborValue value;
        try
        {
            value = CborReader.Read(encoded);
        }
        catch (CborFormatException e)
        {
            throw new CoseKeyException("COSE_Key is not well-formed CBOR: " + e.Message, e);
        }
        if (value is not CborMap map)
        {
            throw new CoseKeyException("COSE_Key must be a CBOR map.");
        }
        return From(map);
    }

    /// <summary>
    /// Builds a key from an already decoded COSE_Key map.
    /// </summary>
    /// <param name="map">The decoded map.</param>
    /// <returns>The parsed key.</returns>
    /// <exception cref="CoseKeyException">The key is not supported or is invalid.</exception>
    public static CoseKey From(CborMap map)
    {
        ArgumentNullException.ThrowIfNull(map);
        long keyType = RequireInteger(map, LabelKty, "kty");
        long algorithmNumber = RequireInteger(map, LabelAlg, "alg");
        if (!CoseAlgorithms.IsSupported(algorithmNumber))
        {
            throw new CoseKeyException($"Unsupported COSE algorithm {algorithmNumber}.");
        }
        CoseAlgorithm algorithm = (CoseAlgorithm)algorithmNumber;
        if (keyType != CoseAlgorithms.KeyType(algorithm))
        {
            throw new CoseKeyException($"COSE key type {keyType} does not match algorithm {algorithm}.");
        }

        if (keyType == CoseAlgorithms.KeyTypeEc2)
        {
            long curve = RequireInteger(map, LabelCrv, "crv");
            if (curve != CoseAlgorithms.CurveIdentifier(algorithm))
            {
                throw new CoseKeyException($"COSE curve {curve} does not match algorithm {algorithm}.");
            }
            byte[] x = RequireBytes(map, LabelX, "x");
            byte[] y = RequireBytes(map, LabelY, "y");
            int fieldSize = FieldSizeBytes(algorithm);
            if (x.Length != fieldSize || y.Length != fieldSize)
            {
                throw new CoseKeyException($"EC2 coordinates for {algorithm} must be {fieldSize} bytes each.");
            }
            return new CoseKey(keyType, algorithm, curve, x, y, null, null);
        }

        byte[] modulus = RequireBytes(map, LabelN, "n");
        byte[] exponent = RequireBytes(map, LabelE, "e");
        if (modulus.Length < MinimumRsaModulusBytes || (modulus[0] & 0x80) == 0 || (modulus[^1] & 1) == 0)
        {
            throw new CoseKeyException($"RSA modulus must be an odd integer of at least {MinimumRsaModulusBytes * 8} bits (big-endian, no leading zero byte, top bit set).");
        }
        if (exponent.Length == 0 || exponent.Length > 8 || exponent[0] == 0 || (exponent[^1] & 1) == 0 || (exponent.Length == 1 && exponent[0] < 3))
        {
            throw new CoseKeyException("RSA public exponent must be an odd integer of at least 3 and at most 8 bytes, with no leading zero byte.");
        }
        return new CoseKey(keyType, algorithm, null, null, null, modulus, exponent);
    }

    /// <summary>
    /// Converts the key to the framework public-key type: an <see cref="EccPublicKey"/> on the
    /// named curve (validated to lie on the curve) or an <see cref="RsaPublicKey"/>.
    /// </summary>
    /// <returns>The public key.</returns>
    /// <exception cref="CoseKeyException">The key material is not a valid public key.</exception>
    public IPublicKey ToPublicKey()
    {
        try
        {
            if (KeyType == CoseAlgorithms.KeyTypeEc2)
            {
                string curveName = CoseAlgorithms.CurveName(Algorithm)!;
                X9ECParameters parameters = ECNamedCurveTable.GetByName(curveName);
                DerObjectIdentifier oid = ECNamedCurveTable.GetOid(curveName);
                ECNamedDomainParameters domain = new ECNamedDomainParameters(oid, parameters);
                byte[] encodedPoint = new byte[1 + X!.Length + Y!.Length];
                encodedPoint[0] = 0x04;
                Array.Copy(X, 0, encodedPoint, 1, X.Length);
                Array.Copy(Y, 0, encodedPoint, 1 + X.Length, Y.Length);
                ECPoint point = parameters.Curve.DecodePoint(encodedPoint);
                if (point.IsInfinity || !point.IsValid())
                {
                    throw new CoseKeyException("EC2 point is not on the curve.");
                }
                return new EccPublicKey(new ECPublicKeyParameters(point, domain));
            }

            RsaKeyParameters rsa = new RsaKeyParameters(false, new BigInteger(1, Modulus), new BigInteger(1, Exponent));
            return new RsaPublicKey(rsa.ToPem());
        }
        catch (CoseKeyException)
        {
            throw;
        }
        catch (Exception e)
        {
            throw new CoseKeyException("COSE key material is not a valid public key: " + e.Message, e);
        }
    }

    /// <summary>
    /// Encodes the key back to its COSE_Key map (the inverse of <see cref="From"/>), which lets
    /// hosts and tests emit the same structure an authenticator would.
    /// </summary>
    /// <returns>The map value.</returns>
    public CborMap ToCbor()
    {
        if (KeyType == CoseAlgorithms.KeyTypeEc2)
        {
            return CborWriter.Map(
                CborWriter.Entry(LabelKty, new CborInteger(KeyType)),
                CborWriter.Entry(LabelAlg, new CborInteger((long)Algorithm)),
                CborWriter.Entry(LabelCrv, new CborInteger(Curve!.Value)),
                CborWriter.Entry(LabelX, new CborBytes(X!)),
                CborWriter.Entry(LabelY, new CborBytes(Y!)));
        }
        return CborWriter.Map(
            CborWriter.Entry(LabelKty, new CborInteger(KeyType)),
            CborWriter.Entry(LabelAlg, new CborInteger((long)Algorithm)),
            CborWriter.Entry(LabelN, new CborBytes(Modulus!)),
            CborWriter.Entry(LabelE, new CborBytes(Exponent!)));
    }

    /// <summary>
    /// Builds the COSE_Key for an existing EC public key on a supported curve.
    /// </summary>
    /// <param name="publicKey">The EC public key.</param>
    /// <param name="algorithm">The ECDSA algorithm the key will be used with.</param>
    /// <returns>The COSE key.</returns>
    /// <exception cref="CoseKeyException">The algorithm is not an ECDSA algorithm, or the key is not on the curve the algorithm requires.</exception>
    public static CoseKey FromEcc(EccPublicKey publicKey, CoseAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        long? curve = CoseAlgorithms.CurveIdentifier(algorithm);
        string? curveName = CoseAlgorithms.CurveName(algorithm);
        if (curve is null || curveName is null)
        {
            throw new CoseKeyException($"{algorithm} is not an ECDSA algorithm.");
        }
        ECCurve required = ECNamedCurveTable.GetByName(curveName).Curve;
        if (!required.Equals(publicKey.EcValue.Parameters.Curve))
        {
            throw new CoseKeyException($"The key is not on {curveName}, the curve {algorithm} requires.");
        }
        ECPoint point = publicKey.EcValue.Q.Normalize();
        int fieldSize = FieldSizeBytes(algorithm);
        byte[] x = BigIntegers.AsUnsignedByteArray(fieldSize, point.AffineXCoord.ToBigInteger());
        byte[] y = BigIntegers.AsUnsignedByteArray(fieldSize, point.AffineYCoord.ToBigInteger());
        return new CoseKey(CoseAlgorithms.KeyTypeEc2, algorithm, curve, x, y, null, null);
    }

    /// <summary>
    /// Builds the RS256 COSE_Key for an existing RSA public key.
    /// </summary>
    /// <param name="publicKey">The RSA public key.</param>
    /// <returns>The COSE key.</returns>
    public static CoseKey FromRsa(RsaPublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        RsaKeyParameters rsa = (RsaKeyParameters)publicKey.Value;
        return new CoseKey(CoseAlgorithms.KeyTypeRsa, CoseAlgorithm.RS256, null, null, null,
            rsa.Modulus.ToByteArrayUnsigned(), rsa.Exponent.ToByteArrayUnsigned());
    }

    private static int FieldSizeBytes(CoseAlgorithm algorithm)
    {
        switch (algorithm)
        {
            case CoseAlgorithm.ES256:
                return 32;
            case CoseAlgorithm.ES384:
                return 48;
            case CoseAlgorithm.ES512:
                return 66;
            default:
                throw new CoseKeyException($"{algorithm} has no field size.");
        }
    }

    private static long RequireInteger(CborMap map, long label, string name)
    {
        CborValue? value = map[label];
        if (value is not CborInteger integer)
        {
            throw new CoseKeyException($"COSE_Key is missing integer parameter '{name}' (label {label}).");
        }
        return integer.Value;
    }

    private static byte[] RequireBytes(CborMap map, long label, string name)
    {
        CborValue? value = map[label];
        if (value is not CborBytes bytes)
        {
            throw new CoseKeyException($"COSE_Key is missing byte-string parameter '{name}' (label {label}).");
        }
        return bytes.Value;
    }
}

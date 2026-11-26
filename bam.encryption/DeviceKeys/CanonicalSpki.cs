using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Bam.Encryption.DeviceKeys;

/// <summary>
/// Canonical encoding and fingerprint of a P-256 public key. Every device-key store and every verifier must agree on
/// a key's fingerprint byte for byte, and the same key can arrive in several DER forms (explicit curve parameters,
/// a compressed point). This turns any of them into one form: DER SubjectPublicKeyInfo with the named-curve OID
/// and an uncompressed point. That is the form bam.protocol's <c>PublicKeyFingerprint.Of</c> hashes, so
/// <see cref="FingerprintOf"/> returns the same value it does.
/// </summary>
public static class CanonicalSpki
{
    private static readonly DerObjectIdentifier P256Oid = new DerObjectIdentifier(DeviceKeyAlgorithm.CurveOid);

    private static readonly X9ECParameters P256 = ECNamedCurveTable.GetByOid(P256Oid);

    /// <summary>
    /// Returns the canonical form of a P-256 public key given as DER SubjectPublicKeyInfo in any encoding.
    /// </summary>
    /// <param name="spki">The public key.</param>
    /// <returns>The canonical DER, or <see cref="DeviceKeyErrorCategory.InvalidRequest"/> when the bytes are not a
    /// valid P-256 public key.</returns>
    public static DeviceKeyResult<byte[]> Canonicalize(byte[] spki)
    {
        if (spki == null || spki.Length == 0)
        {
            return DeviceKeyResult<byte[]>.Failure(DeviceKeyErrorCategory.InvalidRequest, "No public key was given.");
        }
        AsymmetricKeyParameter key;
        try
        {
            key = PublicKeyFactory.CreateKey(spki);
        }
        catch (Exception)
        {
            // The bytes come from outside (a client's publicKeySpki), and BouncyCastle's parsers throw many types
            // (FormatException from DecodePoint among them), so every parse failure is a refusal, as in bam.protocol's
            // PublicKeyFingerprint.Of.
            return DeviceKeyResult<byte[]>.Failure(DeviceKeyErrorCategory.InvalidRequest, "The bytes are not a DER SubjectPublicKeyInfo.");
        }
        if (key is not ECPublicKeyParameters ecKey)
        {
            return DeviceKeyResult<byte[]>.Failure(DeviceKeyErrorCategory.InvalidRequest, "The key is not an elliptic-curve key.");
        }
        if (!IsP256(ecKey.Parameters))
        {
            return DeviceKeyResult<byte[]>.Failure(DeviceKeyErrorCategory.InvalidRequest, "The key is not on P-256.");
        }
        ECPublicKeyParameters named = new ECPublicKeyParameters("EC", ecKey.Q.Normalize(), P256Oid);
        return DeviceKeyResult<byte[]>.Success(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(named).GetDerEncoded());
    }

    /// <summary>
    /// Returns the fingerprint of a public key: SHA-256 of its canonical DER, as 64 lowercase hex characters.
    /// </summary>
    /// <param name="spki">The public key as DER SubjectPublicKeyInfo, in any encoding.</param>
    /// <returns>The fingerprint, or why the key was refused.</returns>
    public static DeviceKeyResult<string> FingerprintOf(byte[] spki)
    {
        DeviceKeyResult<byte[]> canonical = Canonicalize(spki);
        if (!canonical.Succeeded || canonical.Value == null)
        {
            return DeviceKeyResult<string>.Failure(canonical.Error?.Category ?? DeviceKeyErrorCategory.InvalidRequest, canonical.Error?.Message ?? "The key was refused.");
        }
        return DeviceKeyResult<string>.Success(canonical.Value.Sha256());
    }

    /// <summary>
    /// Builds the public description of a key from its public half, canonicalising it. Stores use this so every
    /// store reports the same <see cref="DeviceKeyInfo.PublicKeySpki"/> and <see cref="DeviceKeyInfo.Fingerprint"/>
    /// for the same key.
    /// </summary>
    /// <param name="id">The key's id.</param>
    /// <param name="spki">The public key, in any DER encoding.</param>
    /// <param name="createdUtc">When the key was created.</param>
    /// <param name="protection">What protects the private key.</param>
    /// <param name="access">The key's access policy.</param>
    /// <returns>The description.</returns>
    /// <exception cref="ArgumentException">The public key is not a valid P-256 key, which means the store itself
    /// produced a wrong key.</exception>
    internal static DeviceKeyInfo Describe(DeviceKeyId id, byte[] spki, DateTimeOffset createdUtc, DeviceKeyProtection protection, DeviceKeyAccess access)
    {
        DeviceKeyResult<byte[]> canonical = Canonicalize(spki);
        if (!canonical.Succeeded || canonical.Value == null)
        {
            throw new ArgumentException($"The store produced an invalid public key: {canonical.Error?.Message}", nameof(spki));
        }
        return new DeviceKeyInfo
        {
            Id = id,
            PublicKeySpki = canonical.Value,
            Fingerprint = canonical.Value.Sha256(),
            CreatedUtc = new DateTimeOffset(createdUtc.UtcDateTime.Ticks - (createdUtc.UtcDateTime.Ticks % TimeSpan.TicksPerSecond), TimeSpan.Zero),
            Protection = protection,
            Access = access,
        };
    }

    private static bool IsP256(ECDomainParameters domain)
    {
        if (domain is ECNamedDomainParameters namedDomain)
        {
            return namedDomain.Name.Equals(P256Oid);
        }
        return domain.Curve.Equals(P256.Curve)
            && domain.G.Equals(P256.G)
            && domain.N.Equals(P256.N)
            && (domain.H == null || domain.H.Equals(P256.H));
    }
}

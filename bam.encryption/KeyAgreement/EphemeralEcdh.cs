using System.Security.Cryptography;
using Bam.Encryption.DeviceKeys;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;

namespace Bam.Encryption;

/// <summary>
/// A one-use P-256 key pair for a session key agreement (bam.encryption#38). It agrees with a peer's public key
/// once, and the shared secret never leaves the library: the only thing a caller can do with it is derive keys
/// through HKDF (<see cref="EcdhAgreement.DeriveKey(byte[], string, int)"/>).
/// </summary>
/// <remarks>
/// The secret given to HKDF is the 32-byte X coordinate of the shared point, big-endian, with leading zero bytes
/// kept (bam.protocol#118). This is a separate path from <c>EccPublicPrivateKeyPair</c>'s, which uses the raw secret
/// as an AES key (bam.encryption#3).
/// </remarks>
public sealed class EphemeralEcdh : IDisposable
{
    /// <summary>The shared secret's length in bytes.</summary>
    public const int SecretLength = 32;

    private static readonly X9ECParameters P256 = ECNamedCurveTable.GetByOid(new Org.BouncyCastle.Asn1.DerObjectIdentifier(DeviceKeyAlgorithm.CurveOid));

    private readonly ECDiffieHellman key;
    private bool used;
    private bool disposed;

    private EphemeralEcdh(ECDiffieHellman key)
    {
        this.key = key;
        PublicKeySpki = key.ExportSubjectPublicKeyInfo();
    }

    /// <summary>
    /// The public key, as DER SubjectPublicKeyInfo with the named curve and an uncompressed point
    /// (<see cref="CanonicalSpki"/>'s form). Send this to the peer.
    /// </summary>
    public byte[] PublicKeySpki { get; }

    /// <summary>
    /// Generates a key pair.
    /// </summary>
    /// <returns>The key pair.</returns>
    public static EphemeralEcdh Generate()
    {
        return new EphemeralEcdh(ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256));
    }

    /// <summary>
    /// Builds a key pair from a fixed private scalar, for known-answer tests only. A real session always uses
    /// <see cref="Generate"/>.
    /// </summary>
    /// <param name="privateScalar">The 32-byte big-endian scalar, from 1 to n - 1.</param>
    /// <returns>The key pair.</returns>
    /// <exception cref="ArgumentException">The scalar is not 32 bytes or is out of range.</exception>
    internal static EphemeralEcdh FromPrivateScalar(byte[] privateScalar)
    {
        ArgumentNullException.ThrowIfNull(privateScalar);
        if (privateScalar.Length != SecretLength)
        {
            throw new ArgumentException($"A P-256 private scalar is {SecretLength} bytes.", nameof(privateScalar));
        }
        BigInteger d = new BigInteger(1, privateScalar);
        if (d.SignValue <= 0 || d.CompareTo(P256.N) >= 0)
        {
            throw new ArgumentException("The private scalar is out of range.", nameof(privateScalar));
        }
        Org.BouncyCastle.Math.EC.ECPoint q = P256.G.Multiply(d).Normalize();
        ECParameters parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = (byte[])privateScalar.Clone(),
            Q = new ECPoint { X = q.AffineXCoord.GetEncoded(), Y = q.AffineYCoord.GetEncoded() },
        };
        ECDiffieHellman key = ECDiffieHellman.Create();
        try
        {
            key.ImportParameters(parameters);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(parameters.D);
        }
        return new EphemeralEcdh(key);
    }

    /// <summary>
    /// Agrees a shared secret with a peer's public key. A key pair agrees once; a second call throws, so one
    /// ephemeral key never serves two sessions.
    /// </summary>
    /// <param name="peerPublicKeySpki">The peer's P-256 public key as DER SubjectPublicKeyInfo, in any encoding
    /// <see cref="CanonicalSpki.Canonicalize"/> accepts.</param>
    /// <returns>The agreement, or why the peer's key was refused (not P-256, not a valid point, not a key at
    /// all). A refusal does not use up the key pair.</returns>
    /// <exception cref="InvalidOperationException">The key pair has already agreed.</exception>
    /// <exception cref="ObjectDisposedException">The key pair was disposed.</exception>
    public EcdhAgreementResult Agree(byte[] peerPublicKeySpki)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (used)
        {
            throw new InvalidOperationException("An ephemeral key agrees once; generate a new one for each session.");
        }
        DeviceKeyResult<byte[]> canonical = CanonicalSpki.Canonicalize(peerPublicKeySpki);
        if (!canonical.Succeeded || canonical.Value == null)
        {
            return EcdhAgreementResult.Refused(canonical.Error?.Message ?? "The peer's public key was refused.");
        }
        byte[] secret;
        try
        {
            using ECDiffieHellman peer = ECDiffieHellman.Create();
            peer.ImportSubjectPublicKeyInfo(canonical.Value, out _);
            secret = key.DeriveRawSecretAgreement(peer.PublicKey);
        }
        catch (CryptographicException)
        {
            return EcdhAgreementResult.Refused("The peer's public key is not a valid P-256 point.");
        }
        if (secret.Length != SecretLength)
        {
            CryptographicOperations.ZeroMemory(secret);
            return EcdhAgreementResult.Refused($"The platform returned a {secret.Length}-byte secret, not {SecretLength}.");
        }
        used = true;
        return EcdhAgreementResult.Agreed(new EcdhAgreement(secret));
    }

    /// <summary>
    /// Releases the private key.
    /// </summary>
    public void Dispose()
    {
        if (!disposed)
        {
            disposed = true;
            key.Dispose();
        }
    }
}

/// <summary>
/// A shared secret from <see cref="EphemeralEcdh.Agree"/>. The secret can only be passed to HKDF. Dispose it once
/// the session's keys are derived; that clears it.
/// </summary>
public sealed class EcdhAgreement : IDisposable
{
    private readonly byte[] secret;
    private bool disposed;

    internal EcdhAgreement(byte[] secret)
    {
        this.secret = secret;
    }

    /// <summary>
    /// Derives key bytes from the secret with <see cref="KeyDerivation.Hkdf(ReadOnlySpan{byte}, ReadOnlySpan{byte}, string, int)"/>.
    /// </summary>
    /// <param name="salt">The salt; not empty. Sealed frames use SHA-256 of the session transcript.</param>
    /// <param name="label">The purpose label, for example <c>BAM-SEALED-FRAME-1 client-to-server</c>.</param>
    /// <param name="length">How many bytes to return.</param>
    /// <returns>The key bytes.</returns>
    /// <exception cref="ObjectDisposedException">The agreement was disposed.</exception>
    public byte[] DeriveKey(byte[] salt, string label, int length)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(salt);
        return KeyDerivation.Hkdf(secret, salt, label, length);
    }

    /// <summary>
    /// Derives an AES-256-GCM key from the secret.
    /// </summary>
    /// <param name="salt">The salt; not empty.</param>
    /// <param name="label">The purpose label.</param>
    /// <returns>The key.</returns>
    public AeadKey DeriveAeadKey(byte[] salt, string label)
    {
        byte[] bytes = DeriveKey(salt, label, AeadKey.KeyLength);
        try
        {
            return new AeadKey(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Clears the secret.
    /// </summary>
    public void Dispose()
    {
        if (!disposed)
        {
            disposed = true;
            CryptographicOperations.ZeroMemory(secret);
        }
    }
}

/// <summary>
/// The result of <see cref="EphemeralEcdh.Agree"/>.
/// </summary>
public sealed class EcdhAgreementResult
{
    private EcdhAgreementResult(EcdhAgreement? agreement, string reason)
    {
        Agreement = agreement;
        Reason = reason;
    }

    /// <summary>True when the peer's key was accepted.</summary>
    public bool Succeeded => Agreement != null;

    /// <summary>The agreement when accepted, otherwise null.</summary>
    public EcdhAgreement? Agreement { get; }

    /// <summary>Why the peer's key was refused, or an empty string.</summary>
    public string Reason { get; }

    internal static EcdhAgreementResult Agreed(EcdhAgreement agreement) => new EcdhAgreementResult(agreement, string.Empty);

    internal static EcdhAgreementResult Refused(string reason) => new EcdhAgreementResult(null, reason);
}

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Text;

namespace Bam.Encryption;

/// <summary>
/// Represents an ECC public/private key pair using the prime256v1 curve, supporting ECDH shared secret derivation and disposable key material.
/// </summary>
public class EccPublicPrivateKeyPair : IEccKeySource, IDisposable
{
    private bool _disposed = false;

    /// <summary>
    /// Initializes a new instance of the <see cref="EccPublicPrivateKeyPair"/> class, generating a new ECC key pair.
    /// </summary>
    public EccPublicPrivateKeyPair()
    {
        this.AsymmetricCipherKeyPair = Generate();
        this.Pem = AsymmetricCipherKeyPair.ToPem(Encoding.UTF8);
        this.PublicKeyPem = AsymmetricCipherKeyPair.PublicKeyToPem();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="EccPublicPrivateKeyPair"/> class from PEM-encoded key data.
    /// </summary>
    /// <param name="pem">The PEM-encoded key pair as a byte array.</param>
    public EccPublicPrivateKeyPair(byte[] pem)
    {
        this.Pem = pem;
        this.AsymmetricCipherKeyPair = pem.PemToKeyPair();
        this.PublicKeyPem = AsymmetricCipherKeyPair.PublicKeyToPem();
    }

    AsymmetricCipherKeyPair? _asymmetricCipherKeyPair;
    protected internal AsymmetricCipherKeyPair AsymmetricCipherKeyPair
    {
        get => _asymmetricCipherKeyPair ??= Pem.PemToKeyPair();
        set => _asymmetricCipherKeyPair = value;
    }

    protected internal byte[] Pem { get; private set; }

    /// <summary>
    /// Gets the PEM-encoded public key string.
    /// </summary>
    public string PublicKeyPem { get; private set; }

    /// <summary>
    /// Derives a shared AES key using ECDH key agreement with the other party's public key.
    /// </summary>
    /// <param name="otherPublicPemString">The PEM-encoded public key of the other party.</param>
    /// <returns>An AES key derived from the shared secret.</returns>
    public AesKey GetSharedAesKey(string otherPublicPemString)
    {
        byte[] sharedSecret = GetSharedSecret(otherPublicPemString);
        return CreateSharedAesKey(sharedSecret);
    }
    
    /// <summary>
    /// Computes the ECDH shared secret with the other party's PEM-encoded public key.
    /// </summary>
    /// <param name="otherPublicPemString">The PEM-encoded public key of the other party.</param>
    /// <returns>The shared secret as a byte array.</returns>
    public byte[] GetSharedSecret(string otherPublicPemString)
    {
        return GetSharedSecret((ECPublicKeyParameters)otherPublicPemString.PemToKey());
    }

    /// <summary>
    /// Computes the ECDH shared secret with the other party's EC public key parameters.
    /// </summary>
    /// <param name="otherPublicKey">The EC public key parameters of the other party.</param>
    /// <returns>The shared secret as a byte array.</returns>
    public byte[] GetSharedSecret(ECPublicKeyParameters otherPublicKey)
    {
        IBasicAgreement agreement = AgreementUtilities.GetBasicAgreement("ECDH");
        agreement.Init(AsymmetricCipherKeyPair.Private);
        BigInteger sharedSecret1 = agreement.CalculateAgreement(otherPublicKey);
        return sharedSecret1.ToByteArrayUnsigned();
    }
    
    /// <summary>
    /// Generates a new ECC key pair using the prime256v1 curve.
    /// </summary>
    /// <returns>The generated asymmetric cipher key pair.</returns>
    public static AsymmetricCipherKeyPair Generate()
    {
        X9ECParameters ecParams = ECNamedCurveTable.GetByName("prime256v1");
        ECDomainParameters domainParams = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H, ecParams.GetSeed());

        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(domainParams, new SecureRandom());
        ECKeyPairGenerator ecKeyGen = new ECKeyPairGenerator();
        ecKeyGen.Init(keyGenParams);
        return ecKeyGen.GenerateKeyPair();
    }
    
    private static AesKey CreateSharedAesKey(byte[] sharedSecret)
    {
        string hex = sharedSecret.ToHexString();
        Span<byte> bytes = Hmac.Sha256(hex, hex);
        return new AesKey(sharedSecret, bytes.Slice(0, 16).ToArray());
    }

    /// <inheritdoc />
    public EccPublicPrivateKeyPair GetEccKey()
    {
        return this;
    }

    /// <inheritdoc />
    public EccPublicKey GetEccPublicKey()
    {
        return new EccPublicKey(PublicKeyPem);
    }

    /// <summary>
    /// Securely clears the PEM key data from memory and releases resources.
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            if (Pem != null)
            {
                Array.Clear(Pem, 0, Pem.Length);
            }

            _asymmetricCipherKeyPair = null;
        }

        _disposed = true;
    }
}
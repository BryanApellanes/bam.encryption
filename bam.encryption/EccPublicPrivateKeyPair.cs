using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Text;

namespace Bam.Encryption;

public class EccPublicPrivateKeyPair : IEccKeySource, IDisposable
{
    private bool _disposed = false;

    public EccPublicPrivateKeyPair()
    {
        this.AsymmetricCipherKeyPair = Generate();
        this.Pem = AsymmetricCipherKeyPair.ToPem(Encoding.UTF8);
        this.PublicKeyPem = AsymmetricCipherKeyPair.PublicKeyToPem();
    }

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

    public string PublicKeyPem { get; private set; }

    public AesKey GetSharedAesKey(string otherPublicPemString)
    {
        byte[] sharedSecret = GetSharedSecret(otherPublicPemString);
        return CreateSharedAesKey(sharedSecret);
    }
    
    public byte[] GetSharedSecret(string otherPublicPemString)
    {
        return GetSharedSecret((ECPublicKeyParameters)otherPublicPemString.PemToKey());
    }

    public byte[] GetSharedSecret(ECPublicKeyParameters otherPublicKey)
    {
        IBasicAgreement agreement = AgreementUtilities.GetBasicAgreement("ECDH");
        agreement.Init(AsymmetricCipherKeyPair.Private);
        BigInteger sharedSecret1 = agreement.CalculateAgreement(otherPublicKey);
        return sharedSecret1.ToByteArrayUnsigned();
    }
    
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

    public EccPublicPrivateKeyPair GetEccKey()
    {
        return this;
    }

    public EccPublicKey GetEccPublicKey()
    {
        return new EccPublicKey(PublicKeyPem);
    }

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
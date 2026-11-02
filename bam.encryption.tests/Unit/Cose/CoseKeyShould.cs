using Bam.Encryption.Cose;
using Bam.Encryption.Tests.TestClasses;
using Bam.Test;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Bam.Encryption.Tests.Unit.Cose;

[UnitTestMenu("CoseKeyShould", Selector = "cosek")]
public class CoseKeyShould : UnitTestMenuContainer
{
    [UnitTest]
    public void RoundTripEs256Key()
    {
        After.Setup(reg =>
        {
            reg.Set(new EccPublicPrivateKeyPair());
        })
        .When<EccPublicPrivateKeyPair>("encodes an ES256 COSE key and parses it back", (keyPair, reg) =>
        {
            EccPublicKey original = keyPair.GetEccPublicKey();
            CoseKey cose = CoseKey.FromEcc(original, CoseAlgorithm.ES256);
            byte[] encoded = CborWriter.Encode(cose.ToCbor());
            CoseKey parsed = CoseKey.Parse(encoded);
            IPublicKey restored = parsed.ToPublicKey();
            byte[] payload = new byte[] { 1, 2, 3, 4, 5 };
            ISigner signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(true, new EccPrivateKey(keyPair).Value);
            signer.BlockUpdate(payload, 0, payload.Length);
            byte[] signature = signer.GenerateSignature();
            ISignatureVerification crossCheck = new DetachedSignatureVerifier().Verify(payload, signature, restored, "SHA-256withECDSA");
            return new EcRoundTripOutcome(original, cose, parsed, restored, crossCheck.Success);
        })
        .TheTest
        .ShouldPass<EcRoundTripOutcome>((because, outcome) =>
        {
            because.ItsTrue("key type is EC2", outcome.Parsed.KeyType == CoseAlgorithms.KeyTypeEc2);
            because.ItsTrue("algorithm is ES256", outcome.Parsed.Algorithm == CoseAlgorithm.ES256);
            because.ItsTrue("curve is P-256", outcome.Parsed.Curve == CoseAlgorithms.CurveP256);
            because.ItsTrue("x is 32 bytes", outcome.Parsed.X!.Length == 32);
            because.ItsTrue("y is 32 bytes", outcome.Parsed.Y!.Length == 32);
            because.ItsTrue("coordinates survive the round trip", outcome.Parsed.X.AsSpan().SequenceEqual(outcome.Cose.X) && outcome.Parsed.Y.AsSpan().SequenceEqual(outcome.Cose.Y));
            because.ItsTrue("restored key is an EccPublicKey", outcome.Restored is EccPublicKey);
            because.ItsTrue("restored point equals the original point", ((EccPublicKey)outcome.Restored).EcValue.Q.Equals(outcome.Original.EcValue.Q));
            because.ItsTrue("restored PEM names the curve rather than spelling out its parameters", outcome.Restored.Pem.Length < outcome.Original.Pem.Length);
            because.ItsTrue("a signature by the original private key verifies under the restored key", outcome.SignatureVerifiesUnderRestoredKey);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RoundTripEs384Key()
    {
        After.Setup(reg =>
        {
            reg.Set(new CborVectors());
        })
        .When<CborVectors>("encodes an ES384 COSE key from a P-384 pair and parses it back", (vectors, reg) =>
        {
            X9ECParameters curve = ECNamedCurveTable.GetByName("secp384r1");
            ECDomainParameters domain = new ECDomainParameters(curve);
            ECKeyPairGenerator generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
            AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
            EccPublicKey original = new EccPublicKey(pair.Public);
            CoseKey cose = CoseKey.FromEcc(original, CoseAlgorithm.ES384);
            CoseKey parsed = CoseKey.Parse(CborWriter.Encode(cose.ToCbor()));
            IPublicKey restored = parsed.ToPublicKey();
            return new EcRoundTripOutcome(original, cose, parsed, restored, true);
        })
        .TheTest
        .ShouldPass<EcRoundTripOutcome>((because, outcome) =>
        {
            because.ItsTrue("curve is P-384", outcome.Parsed.Curve == CoseAlgorithms.CurveP384);
            because.ItsTrue("coordinates are 48 bytes", outcome.Parsed.X!.Length == 48 && outcome.Parsed.Y!.Length == 48);
            because.ItsTrue("restored point equals the original point", ((EccPublicKey)outcome.Restored).EcValue.Q.Equals(outcome.Original.EcValue.Q));
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RoundTripRs256Key()
    {
        After.Setup(reg =>
        {
            reg.Set(new RsaPublicPrivateKeyPair(RsaKeyLength._2048));
        })
        .When<RsaPublicPrivateKeyPair>("encodes an RS256 COSE key and parses it back", (keyPair, reg) =>
        {
            RsaPublicKey original = keyPair.GetRsaPublicKey();
            CoseKey cose = CoseKey.FromRsa(original);
            CoseKey parsed = CoseKey.Parse(CborWriter.Encode(cose.ToCbor()));
            IPublicKey restored = parsed.ToPublicKey();
            return new RsaRoundTripOutcome(original, parsed, restored);
        })
        .TheTest
        .ShouldPass<RsaRoundTripOutcome>((because, outcome) =>
        {
            because.ItsTrue("key type is RSA", outcome.Parsed.KeyType == CoseAlgorithms.KeyTypeRsa);
            because.ItsTrue("algorithm is RS256", outcome.Parsed.Algorithm == CoseAlgorithm.RS256);
            because.ItsTrue("modulus is 256 bytes", outcome.Parsed.Modulus!.Length == 256);
            because.ItsTrue("exponent is 65537", outcome.Parsed.Exponent!.AsSpan().SequenceEqual(new byte[] { 0x01, 0x00, 0x01 }));
            because.ItsTrue("restored key is an RsaPublicKey", outcome.Restored is RsaPublicKey);
            because.ItsTrue("restored PEM equals the original PEM", outcome.Restored.Pem == outcome.Original.Pem);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RejectInvalidKeys()
    {
        After.Setup(reg =>
        {
            reg.Set(new EccPublicPrivateKeyPair());
        })
        .When<EccPublicPrivateKeyPair>("parses each invalid COSE key", (keyPair, reg) =>
        {
            CoseKey good = CoseKey.FromEcc(keyPair.GetEccPublicKey(), CoseAlgorithm.ES256);
            byte[] x = good.X!;
            byte[] y = good.Y!;
            byte[] offCurveY = (byte[])y.Clone();
            offCurveY[0] ^= 0x01;
            byte[] modulus = new byte[256];
            Array.Fill(modulus, (byte)0x7f);
            byte[] shortModulus = new byte[128];
            Array.Fill(shortModulus, (byte)0x7f);
            byte[] leadingZeroModulus = (byte[])modulus.Clone();
            leadingZeroModulus[0] = 0;
            return new RejectionOutcome(
                Rejects(Ec(2, -8, 1, x, y)),
                Rejects(Ec(3, -7, 1, x, y)),
                Rejects(Ec(2, -7, 2, x, y)),
                Rejects(Ec(2, -7, 1, x[..31], y)),
                RejectsConversion(Ec(2, -7, 1, x, offCurveY)),
                Rejects(CborWriter.Encode(CborWriter.Map(CborWriter.Entry(1, new CborInteger(2)), CborWriter.Entry(3, new CborInteger(-7)), CborWriter.Entry(-1, new CborInteger(1)), CborWriter.Entry(-2, new CborBytes(x))))),
                Rejects(new byte[] { 0x00 }),
                Rejects(new byte[] { 0xa1 }),
                Rejects(Rsa(shortModulus, new byte[] { 1, 0, 1 })),
                Rejects(Rsa(leadingZeroModulus, new byte[] { 1, 0, 1 })),
                Rejects(Rsa(modulus, new byte[] { 1, 0, 0 })),
                Rejects(Rsa(modulus, new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 1 })),
                !Rejects(Ec(2, -7, 1, x, y)),
                !Rejects(Rsa(modulus, new byte[] { 1, 0, 1 })));
        })
        .TheTest
        .ShouldPass<RejectionOutcome>((because, outcome) =>
        {
            because.ItsTrue("unsupported algorithm is refused", outcome.UnsupportedAlgorithm);
            because.ItsTrue("key type not matching the algorithm is refused", outcome.KeyTypeMismatch);
            because.ItsTrue("curve not matching the algorithm is refused", outcome.CurveMismatch);
            because.ItsTrue("short coordinate is refused", outcome.ShortCoordinate);
            because.ItsTrue("point off the curve is refused on conversion", outcome.OffCurve);
            because.ItsTrue("missing y is refused", outcome.MissingParameter);
            because.ItsTrue("non-map is refused", outcome.NotAMap);
            because.ItsTrue("malformed CBOR is refused as a key error", outcome.Malformed);
            because.ItsTrue("short RSA modulus is refused", outcome.ShortModulus);
            because.ItsTrue("RSA modulus with a leading zero is refused", outcome.LeadingZeroModulus);
            because.ItsTrue("even RSA exponent is refused", outcome.EvenExponent);
            because.ItsTrue("oversized RSA exponent is refused", outcome.LongExponent);
            because.ItsTrue("valid EC key is accepted", outcome.ValidEc);
            because.ItsTrue("valid RSA key is accepted", outcome.ValidRsa);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static byte[] Ec(long keyType, long algorithm, long curve, byte[] x, byte[] y)
    {
        return CborWriter.Encode(CborWriter.Map(
            CborWriter.Entry(1, new CborInteger(keyType)),
            CborWriter.Entry(3, new CborInteger(algorithm)),
            CborWriter.Entry(-1, new CborInteger(curve)),
            CborWriter.Entry(-2, new CborBytes(x)),
            CborWriter.Entry(-3, new CborBytes(y))));
    }

    private static byte[] Rsa(byte[] modulus, byte[] exponent)
    {
        return CborWriter.Encode(CborWriter.Map(
            CborWriter.Entry(1, new CborInteger(3)),
            CborWriter.Entry(3, new CborInteger(-257)),
            CborWriter.Entry(-1, new CborBytes(modulus)),
            CborWriter.Entry(-2, new CborBytes(exponent))));
    }

    private static bool Rejects(byte[] encoded)
    {
        try
        {
            CoseKey.Parse(encoded);
            return false;
        }
        catch (CoseKeyException)
        {
            return true;
        }
    }

    private static bool RejectsConversion(byte[] encoded)
    {
        try
        {
            CoseKey.Parse(encoded).ToPublicKey();
            return false;
        }
        catch (CoseKeyException)
        {
            return true;
        }
    }

    private sealed record EcRoundTripOutcome(EccPublicKey Original, CoseKey Cose, CoseKey Parsed, IPublicKey Restored, bool SignatureVerifiesUnderRestoredKey);

    private sealed record RsaRoundTripOutcome(RsaPublicKey Original, CoseKey Parsed, IPublicKey Restored);

    private sealed record RejectionOutcome(bool UnsupportedAlgorithm, bool KeyTypeMismatch, bool CurveMismatch, bool ShortCoordinate,
        bool OffCurve, bool MissingParameter, bool NotAMap, bool Malformed, bool ShortModulus, bool LeadingZeroModulus,
        bool EvenExponent, bool LongExponent, bool ValidEc, bool ValidRsa);
}

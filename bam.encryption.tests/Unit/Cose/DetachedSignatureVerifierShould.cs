using System.Text;
using Bam.Encryption.Cose;
using Bam.Test;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Bam.Encryption.Tests.Unit.Cose;

[UnitTestMenu("DetachedSignatureVerifierShould", Selector = "dsv")]
public class DetachedSignatureVerifierShould : UnitTestMenuContainer
{
    [UnitTest]
    public void VerifyEcdsaSignatureOverBinaryPayload()
    {
        After.Setup(reg =>
        {
            reg.Set(new EccPublicPrivateKeyPair());
            reg.Set<IDetachedSignatureVerifier>(new DetachedSignatureVerifier());
        })
        .When<IDetachedSignatureVerifier>("verifies an ES256 signature over bytes that are not text", (verifier, reg) =>
        {
            EccPublicPrivateKeyPair keyPair = reg.Get<EccPublicPrivateKeyPair>();
            byte[] payload = new byte[37 + 32];
            new SecureRandom().NextBytes(payload);
            payload[0] = 0xff;
            byte[] signature = Sign(CoseAlgorithms.SignerName(CoseAlgorithm.ES256), new EccPrivateKey(keyPair).Value, payload);
            byte[] tampered = (byte[])payload.Clone();
            tampered[^1] ^= 0x01;
            EccPublicKey other = new EccPublicPrivateKeyPair().GetEccPublicKey();
            ISignatureVerification good = verifier.Verify(payload, signature, keyPair.GetEccPublicKey(), "SHA-256withECDSA");
            ISignatureVerification badPayload = verifier.Verify(tampered, signature, keyPair.GetEccPublicKey(), "SHA-256withECDSA");
            ISignatureVerification wrongKey = verifier.Verify(payload, signature, other, "SHA-256withECDSA");
            ISignatureVerification wrongAlgorithm = verifier.Verify(payload, signature, keyPair.GetEccPublicKey(), "SHA-384withECDSA");
            ISignatureVerification unknownAlgorithm = verifier.Verify(payload, signature, keyPair.GetEccPublicKey(), "NOT-A-SIGNER");
            ISignatureVerification garbage = verifier.Verify(payload, new byte[] { 1, 2, 3 }, keyPair.GetEccPublicKey(), "SHA-256withECDSA");
            return new VerificationOutcome(payload, good, badPayload, wrongKey, wrongAlgorithm, unknownAlgorithm, garbage);
        })
        .TheTest
        .ShouldPass<VerificationOutcome>((because, outcome) =>
        {
            because.ItsTrue("valid signature verifies", outcome.Good.Success);
            because.ItsTrue("valid result has an empty message", outcome.Good.Message == string.Empty);
            because.ItsTrue("result records the payload as base64", outcome.Good.Signature.Data == Convert.ToBase64String(outcome.Payload));
            because.ItsTrue("result records the algorithm", outcome.Good.Signature.Algorithm == "SHA-256withECDSA");
            because.ItsTrue("tampered payload fails", !outcome.BadPayload.Success);
            because.ItsTrue("wrong key fails", !outcome.WrongKey.Success);
            because.ItsTrue("wrong digest fails", !outcome.WrongAlgorithm.Success);
            because.ItsTrue("unknown signer name fails without throwing", !outcome.UnknownAlgorithm.Success && outcome.UnknownAlgorithm.Message.Length > 0);
            because.ItsTrue("undecodable signature fails without throwing", !outcome.Garbage.Success);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void VerifyRsaSignatureOverBinaryPayload()
    {
        After.Setup(reg =>
        {
            reg.Set(new RsaPublicPrivateKeyPair(RsaKeyLength._2048));
            reg.Set<IDetachedSignatureVerifier>(new DetachedSignatureVerifier());
        })
        .When<IDetachedSignatureVerifier>("verifies an RS256 signature over bytes", (verifier, reg) =>
        {
            RsaPublicPrivateKeyPair keyPair = reg.Get<RsaPublicPrivateKeyPair>();
            byte[] payload = Encoding.UTF8.GetBytes("authenticatorData").Concat(new byte[] { 0, 1, 2, 0xfe }).ToArray();
            byte[] signature = Sign(CoseAlgorithms.SignerName(CoseAlgorithm.RS256), keyPair.GetAsymmetricCipherKeyPair().Private, payload);
            ISignatureVerification good = verifier.Verify(payload, signature, keyPair.GetRsaPublicKey(), "SHA-256withRSA");
            ISignatureVerification ecVerifierOnRsaKey = verifier.Verify(payload, signature, keyPair.GetRsaPublicKey(), "SHA-256withECDSA");
            return new RsaOutcome(good, ecVerifierOnRsaKey);
        })
        .TheTest
        .ShouldPass<RsaOutcome>((because, outcome) =>
        {
            because.ItsTrue("valid RSA signature verifies", outcome.Good.Success);
            because.ItsTrue("ECDSA signer over an RSA key fails without throwing", !outcome.Mismatched.Success && outcome.Mismatched.Message.Length > 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static byte[] Sign(string algorithm, AsymmetricKeyParameter privateKey, byte[] payload)
    {
        ISigner signer = SignerUtilities.GetSigner(algorithm);
        signer.Init(true, privateKey);
        signer.BlockUpdate(payload, 0, payload.Length);
        return signer.GenerateSignature();
    }

    private sealed record VerificationOutcome(byte[] Payload, ISignatureVerification Good, ISignatureVerification BadPayload,
        ISignatureVerification WrongKey, ISignatureVerification WrongAlgorithm, ISignatureVerification UnknownAlgorithm,
        ISignatureVerification Garbage);

    private sealed record RsaOutcome(ISignatureVerification Good, ISignatureVerification Mismatched);
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Bam.Console;
using Bam.Encryption.DeviceKeys;
using Bam.Test;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Bam.Encryption.Tests.Unit;

/// <summary>
/// Pins the session primitives (bam.encryption#38): AES-256-GCM with a caller-supplied nonce, sequence nonces,
/// HKDF-SHA256 and one-use ECDH, against RFC 5869 and the sealed-frame vectors from bam.protocol#118.
/// </summary>
[UnitTestMenu("Session Primitives Should", Selector = "sp")]
public class SessionPrimitivesShould : UnitTestMenuContainer
{
    private const string ClientToServerLabel = "BAM-SEALED-FRAME-1 client-to-server";
    private const string ServerToClientLabel = "BAM-SEALED-FRAME-1 server-to-client";

    private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

    [UnitTest]
    public void DeriveTheRfc5869Vectors()
    {
        When.A<string>("derives RFC 5869 test cases 1 and 2",
            "RFC 5869",
            (_) =>
            {
                byte[] case1 = KeyDerivation.Hkdf(
                    Enumerable.Repeat((byte)0x0b, 22).ToArray(),
                    Convert.FromHexString("000102030405060708090a0b0c"),
                    Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9"),
                    42);
                byte[] case2 = KeyDerivation.Hkdf(Range(0x00, 80), Range(0x60, 80), Range(0xb0, 80), 82);
                return new HkdfOutcome(Convert.ToHexString(case1).ToLowerInvariant(), Convert.ToHexString(case2).ToLowerInvariant());
            })
        .TheTest
        .ShouldPass<HkdfOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("test case 1 gives the RFC's output", outcome.Case1 == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
            because.ItsTrue("test case 2 gives the RFC's output", outcome.Case2 == "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AgreeAndDeriveTheSealedSessionVectors()
    {
        When.A<SessionVectors>("rebuilds each session in sealed-session.json from its private scalars",
            () => ReadVectors<SessionVectors>("sealed-session.json"),
            (vectors) => vectors.Cases.Select(SessionCaseOutcome.For).ToList())
        .TheTest
        .ShouldPass<List<SessionCaseOutcome>>((because, _, outcomes) =>
        {
            because.ItsTrue("there are at least the two cases #118 started with", outcomes.Count >= 2);
            because.ItsTrue("one case's shared secret starts with a zero byte", outcomes.Any(outcome => outcome.SharedStartsWithZero));
            foreach (SessionCaseOutcome outcome in outcomes)
            {
                because.ItsTrue($"{outcome.Name}: the client's public key is the vector's", outcome.ClientKeyMatches);
                because.ItsTrue($"{outcome.Name}: the server's public key is the vector's", outcome.ServerKeyMatches);
                because.ItsTrue($"{outcome.Name}: the transcript TaggedPayload builds is the vector's bytes", outcome.TranscriptMatches);
                because.ItsTrue($"{outcome.Name}: the salt is SHA-256 of the transcript", outcome.SaltMatches);
                because.ItsTrue($"{outcome.Name}: HKDF over the vector's shared secret gives both frame keys", outcome.HkdfFromSharedMatches);
                because.ItsTrue($"{outcome.Name}: the client's agreement gives both frame keys", outcome.ClientKeysMatch);
                because.ItsTrue($"{outcome.Name}: the server's agreement gives both frame keys", outcome.ServerKeysMatch);
            }
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void SealAndOpenTheSealedFrameVectors()
    {
        When.A<FrameVectors>("seals and opens each frame in sealed-frames.json",
            () => ReadVectors<FrameVectors>("sealed-frames.json"),
            (vectors) =>
            {
                using AeadKey clientToServer = new AeadKey(Convert.FromHexString(vectors.KeyClientToServerHex));
                using AeadKey serverToClient = new AeadKey(Convert.FromHexString(vectors.KeyServerToClientHex));
                List<FrameOutcome> outcomes = new List<FrameOutcome>();
                foreach (FrameVector frame in vectors.Frames)
                {
                    FrameDirection direction = frame.Direction == "c2s" ? FrameDirection.ClientToServer : FrameDirection.ServerToClient;
                    AeadKey key = direction == FrameDirection.ClientToServer ? clientToServer : serverToClient;
                    bool built = SequenceNonce.TryCreate(direction, frame.Sequence, out byte[] nonce);
                    byte[] associatedData = Encoding.UTF8.GetBytes(frame.AssociatedData);
                    byte[] plaintext = Convert.FromHexString(frame.PlaintextHex);
                    byte[] expected = frame.Ciphertext.FromBase64UrlEncoded();
                    AeadOpenResult opened = key.Open(nonce, expected, associatedData);
                    outcomes.Add(new FrameOutcome(
                        frame.Name,
                        built && Convert.ToHexString(nonce).Equals(frame.NonceHex, StringComparison.OrdinalIgnoreCase),
                        key.Seal(nonce, plaintext, associatedData).SequenceEqual(expected),
                        opened.Status == AeadOpenStatus.Opened && opened.Plaintext!.SequenceEqual(plaintext)));
                }
                return new FrameSetOutcome(vectors.MaximumFramesPerDirection, outcomes);
            })
        .TheTest
        .ShouldPass<FrameSetOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("the vectors' frame limit is SequenceNonce.SessionFrameLimit", outcome.MaximumFramesPerDirection == SequenceNonce.SessionFrameLimit);
            because.ItsTrue("there are frames to check", outcome.Frames.Count > 0);
            foreach (FrameOutcome frame in outcome.Frames)
            {
                because.ItsTrue($"{frame.Name}: the nonce is the vector's", frame.NonceMatches);
                because.ItsTrue($"{frame.Name}: sealing gives the vector's ciphertext and tag", frame.SealMatches);
                because.ItsTrue($"{frame.Name}: opening gives the plaintext", frame.OpenMatches);
            }
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseEveryAlteredOrMalformedInputWhenOpening()
    {
        When.A<string>("seals a value and opens altered copies of it",
            "a frame",
            (text) =>
            {
                using AeadKey key = AeadKey.Generate();
                using AeadKey otherKey = AeadKey.Generate();
                SequenceNonce.TryCreate(FrameDirection.ClientToServer, 7, out byte[] nonce);
                SequenceNonce.TryCreate(FrameDirection.ClientToServer, 8, out byte[] nextNonce);
                byte[] associatedData = Encoding.UTF8.GetBytes("BAM-SEALED-FRAME-1\nsession\nc2s\n7\napplication/json;last");
                byte[] sealedData = key.Seal(nonce, Encoding.UTF8.GetBytes(text), associatedData);
                byte[] flippedCiphertext = (byte[])sealedData.Clone();
                flippedCiphertext[0] ^= 1;
                byte[] flippedTag = (byte[])sealedData.Clone();
                flippedTag[^1] ^= 0x80;
                List<AeadOpenResult> tampered = new List<AeadOpenResult>
                {
                    key.Open(nonce, flippedCiphertext, associatedData),
                    key.Open(nonce, flippedTag, associatedData),
                    key.Open(nonce, sealedData, Encoding.UTF8.GetBytes("BAM-SEALED-FRAME-1\nsession\nc2s\n7\napplication/json")),
                    key.Open(nextNonce, sealedData, associatedData),
                    otherKey.Open(nonce, sealedData, associatedData),
                    key.Open(nonce, sealedData.AsSpan(1).ToArray(), associatedData),
                };
                List<AeadOpenResult> malformed = new List<AeadOpenResult>
                {
                    key.Open(nonce, sealedData.AsSpan(0, AeadKey.TagLength - 1).ToArray(), associatedData),
                    key.Open(nonce, Array.Empty<byte>(), associatedData),
                    key.Open(nonce.AsSpan(0, 11).ToArray(), sealedData, associatedData),
                };
                AeadOpenResult opened = key.Open(nonce, sealedData, associatedData);
                byte[] emptySealed = key.Seal(nextNonce, Array.Empty<byte>(), Array.Empty<byte>());
                return new OpenOutcome(
                    tampered.Select(result => result.Status).ToList(),
                    malformed.Select(result => result.Status).ToList(),
                    tampered.Concat(malformed).All(result => result.Plaintext == null && !result.Succeeded && result.Reason.Length > 0),
                    opened.Succeeded && Encoding.UTF8.GetString(opened.Plaintext!) == text,
                    sealedData.Length == text.Length + AeadKey.TagLength,
                    emptySealed.Length == AeadKey.TagLength && key.Open(nextNonce, emptySealed, Array.Empty<byte>()).Plaintext!.Length == 0);
            })
        .TheTest
        .ShouldPass<OpenOutcome>((because, _, outcome) =>
        {
            because.ItsTrue($"a changed ciphertext, tag, associated data, nonce, key or a dropped byte is Tampered ({string.Join(",", outcome.Tampered)})", outcome.Tampered.All(status => status == AeadOpenStatus.Tampered));
            because.ItsTrue($"data shorter than a tag, or a short nonce, is Malformed ({string.Join(",", outcome.Malformed)})", outcome.Malformed.All(status => status == AeadOpenStatus.Malformed));
            because.ItsTrue("no refusal carries plaintext, and each says why", outcome.RefusalsCarryNoPlaintext);
            because.ItsTrue("the unaltered value opens", outcome.Opened);
            because.ItsTrue("the sealed value is the plaintext plus a 16-byte tag", outcome.LengthIsPlaintextPlusTag);
            because.ItsTrue("an empty plaintext seals to a bare tag and opens", outcome.EmptyPlaintextRoundTrips);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void BuildSequenceNoncesAndRefuseOnesPastTheLimit()
    {
        When.A<string>("builds nonces at the edges",
            "nonces",
            (_) =>
            {
                bool first = SequenceNonce.TryCreate(FrameDirection.ClientToServer, 0, out byte[] firstNonce);
                bool answer = SequenceNonce.TryCreate(FrameDirection.ServerToClient, 0x0102030405060708, ulong.MaxValue, out byte[] answerNonce);
                bool last = SequenceNonce.TryCreate(FrameDirection.ClientToServer, SequenceNonce.SessionFrameLimit - 1, out byte[] lastNonce);
                bool atLimit = SequenceNonce.TryCreate(FrameDirection.ClientToServer, SequenceNonce.SessionFrameLimit, out byte[] atLimitNonce);
                bool wrapped = SequenceNonce.TryCreate(FrameDirection.ClientToServer, ulong.MaxValue, ulong.MaxValue, out byte[] _);
                bool customLimit = SequenceNonce.TryCreate(FrameDirection.ServerToClient, 3, 3, out byte[] _);
                bool zeroLimit = SequenceNonce.TryCreate(FrameDirection.ServerToClient, 0, 0, out byte[] _);
                bool unknownDirection = SequenceNonce.TryCreate((FrameDirection)3, 0, out byte[] _);
                bool zeroDirection = SequenceNonce.TryCreate((FrameDirection)0, 0, out byte[] _);
                return new NonceOutcome(
                    first ? Convert.ToHexString(firstNonce).ToLowerInvariant() : string.Empty,
                    answer ? Convert.ToHexString(answerNonce).ToLowerInvariant() : string.Empty,
                    last ? Convert.ToHexString(lastNonce).ToLowerInvariant() : string.Empty,
                    atLimit, atLimitNonce.Length, wrapped, customLimit, zeroLimit, unknownDirection, zeroDirection);
            })
        .TheTest
        .ShouldPass<NonceOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("the first client frame's nonce is 00000001 then eight zero bytes", outcome.First == "000000010000000000000000");
            because.ItsTrue("the direction and the sequence are big-endian", outcome.Answer == "000000020102030405060708");
            because.ItsTrue("the last frame the session allows is 2^20 - 1", outcome.Last == "0000000100000000000fffff");
            because.ItsTrue("frame 2^20 is refused, with an empty nonce", !outcome.AtLimit && outcome.AtLimitLength == 0);
            because.ItsTrue("the largest sequence number is refused, so a counter cannot wrap", !outcome.Wrapped);
            because.ItsTrue("the caller's own limit is enforced", !outcome.CustomLimit && !outcome.ZeroLimit);
            because.ItsTrue("an undefined direction is refused", !outcome.UnknownDirection && !outcome.ZeroDirection);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseBadKeysLabelsAndPeers()
    {
        When.A<string>("calls each primitive with bad input",
            "bad input",
            (_) =>
            {
                byte[] secret = RandomNumberGenerator.GetBytes(32);
                byte[] salt = RandomNumberGenerator.GetBytes(32);
                using ECDiffieHellman p384 = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
                using EphemeralEcdh ours = EphemeralEcdh.Generate();
                using AeadKey sealer = AeadKey.Generate();
                EcdhAgreementResult otherCurve = ours.Agree(p384.ExportSubjectPublicKeyInfo());
                EcdhAgreementResult garbage = ours.Agree(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 });
                EcdhAgreementResult empty = ours.Agree(Array.Empty<byte>());
                using EphemeralEcdh peer = EphemeralEcdh.Generate();
                EcdhAgreementResult agreed = ours.Agree(peer.PublicKeySpki);
                bool secondAgreeThrows = Throws<InvalidOperationException>(() => ours.Agree(peer.PublicKeySpki));
                EcdhAgreement agreement = agreed.Agreement!;
                agreement.Dispose();
                return new RefusalOutcome(
                    Throws<ArgumentException>(() => KeyDerivation.Hkdf(secret, salt, Array.Empty<byte>(), 32)),
                    Throws<ArgumentException>(() => KeyDerivation.Hkdf(secret, salt, "  ", 32)),
                    Throws<ArgumentException>(() => KeyDerivation.Hkdf(secret, salt, "label\uD800", 32)),
                    Throws<ArgumentException>(() => KeyDerivation.Hkdf(secret, Array.Empty<byte>(), "label", 32)),
                    Throws<ArgumentException>(() => KeyDerivation.Hkdf(Array.Empty<byte>(), salt, "label", 32)),
                    Throws<ArgumentOutOfRangeException>(() => KeyDerivation.Hkdf(secret, salt, "label", 0))
                        && Throws<ArgumentOutOfRangeException>(() => KeyDerivation.Hkdf(secret, salt, "label", KeyDerivation.MaximumHkdfLength + 1)),
                    KeyDerivation.Hkdf(secret, salt, "label", KeyDerivation.MaximumHkdfLength).Length == KeyDerivation.MaximumHkdfLength,
                    !KeyDerivation.Hkdf(secret, salt, ClientToServerLabel, 32).SequenceEqual(KeyDerivation.Hkdf(secret, salt, ServerToClientLabel, 32)),
                    Throws<ArgumentException>(() => new AeadKey(new byte[16])) && Throws<ArgumentException>(() => new AeadKey(new byte[33])),
                    Throws<ArgumentException>(() => sealer.Seal(new byte[8], Array.Empty<byte>(), Array.Empty<byte>())),
                    !otherCurve.Succeeded && otherCurve.Agreement == null && otherCurve.Reason.Length > 0,
                    !garbage.Succeeded && !empty.Succeeded,
                    agreed.Succeeded,
                    secondAgreeThrows,
                    Throws<ObjectDisposedException>(() => agreement.DeriveKey(salt, "label", 32)),
                    Throws<ArgumentException>(() => EphemeralEcdh.FromPrivateScalar(new byte[32]))
                        && Throws<ArgumentException>(() => EphemeralEcdh.FromPrivateScalar(Convert.FromHexString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"))));
            })
        .TheTest
        .ShouldPass<RefusalOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("HKDF refuses an empty info", outcome.EmptyInfo);
            because.ItsTrue("HKDF refuses a blank label", outcome.BlankLabel);
            because.ItsTrue("HKDF refuses a label that is not valid text", outcome.InvalidLabel);
            because.ItsTrue("HKDF refuses an empty salt", outcome.EmptySalt);
            because.ItsTrue("HKDF refuses an empty secret", outcome.EmptySecret);
            because.ItsTrue("HKDF refuses a length of 0 or past 255 blocks", outcome.LengthOutOfRange);
            because.ItsTrue("HKDF gives the full 255 blocks", outcome.MaximumLength);
            because.ItsTrue("the two direction labels give different keys", outcome.LabelsSeparateKeys);
            because.ItsTrue("an AES key that is not 32 bytes is refused", outcome.WrongKeyLength);
            because.ItsTrue("sealing with a nonce that is not 12 bytes is refused", outcome.WrongNonceLength);
            because.ItsTrue("a peer key on P-384 is refused with a reason", outcome.OtherCurveRefused);
            because.ItsTrue("bytes that are not a key are refused", outcome.GarbageRefused);
            because.ItsTrue("a refusal leaves the key pair usable", outcome.AgreedAfterRefusals);
            because.ItsTrue("an ephemeral key agrees only once", outcome.SecondAgreeThrows);
            because.ItsTrue("a disposed agreement derives nothing", outcome.DisposedAgreementThrows);
            because.ItsTrue("a private scalar of 0 or n is refused", outcome.ScalarOutOfRange);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseNonCanonicalAndOffCurvePeerKeys()
    {
        When.A<SessionVectors>("offers one key pair every non-canonical or invalid peer key, then a good one",
            () => ReadVectors<SessionVectors>("sealed-session.json"),
            (vectors) =>
            {
                using EphemeralEcdh ours = EphemeralEcdh.Generate();
                using EphemeralEcdh peer = EphemeralEcdh.Generate();
                byte[] good = peer.PublicKeySpki;
                byte[] compressedVector = vectors.Refused.Single(refused => refused.Name == "a server key in compressed form").ServerPublicKey.FromBase64UrlEncoded();
                ECPublicKeyParameters parameters = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(good);
                X9ECParameters curve = ECNamedCurveTable.GetByName("P-256");
                byte[] explicitForm = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                    new ECPublicKeyParameters("EC", parameters.Q, new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed()))).GetDerEncoded();
                byte[] offCurve = (byte[])good.Clone();
                offCurve[^1] ^= 1;
                byte[] infinity = Convert.FromHexString("3019301306072a8648ce3d020106082a8648ce3d03010703020000");
                byte[] truncated = good.AsSpan(0, good.Length - 1).ToArray();
                // Well-formed DER whose point is 64 bytes, not 65: the outer and bit-string lengths are adjusted.
                byte[] shortPoint = new byte[] { 0x30, 0x58 }.Concat(good.AsSpan(2, 21).ToArray()).Concat(new byte[] { 0x03, 0x41 }).Concat(good.AsSpan(25, good.Length - 26).ToArray()).ToArray();
                List<EcdhAgreementResult> refusals = new List<EcdhAgreementResult>
                {
                    ours.Agree(compressedVector),
                    ours.Agree(explicitForm),
                    ours.Agree(offCurve),
                    ours.Agree(infinity),
                    ours.Agree(truncated),
                    ours.Agree(shortPoint),
                };
                byte[] mutated = peer.PublicKeySpki;
                mutated[^1] ^= 1;
                EcdhAgreementResult agreed = ours.Agree(good);
                agreed.Agreement?.Dispose();
                return new CanonicalOutcome(
                    refusals.Select(result => result.Succeeded).ToList(),
                    refusals.All(result => result.Agreement == null && result.Reason.Length > 0),
                    refusals[0].Reason.Contains("canonical", StringComparison.Ordinal) && refusals[1].Reason.Contains("canonical", StringComparison.Ordinal),
                    agreed.Succeeded,
                    peer.PublicKeySpki.SequenceEqual(good));
            })
        .TheTest
        .ShouldPass<CanonicalOutcome>((because, _, outcome) =>
        {
            because.ItsTrue($"the vector's compressed key, an explicit-parameters key, an off-curve point, the point at infinity, truncated DER and a well-formed 64-byte point are all refused ({string.Join(",", outcome.Refused)})", outcome.Refused.Count == 6 && outcome.Refused.All(succeeded => !succeeded));
            because.ItsTrue("each refusal says why and carries no agreement", outcome.RefusalsExplained);
            because.ItsTrue("a valid key in another encoding is refused as not canonical", outcome.NonCanonicalNamed);
            because.ItsTrue("the refusals leave the key pair usable", outcome.AgreedAfterRefusals);
            because.ItsTrue("changing a returned public key does not change the key pair's", outcome.PublicKeyIsACopy);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void LetOnlyOneOfTwoRacingAgreesSucceed()
    {
        When.A<string>("races two agreements on one key pair, 200 times",
            "race",
            (_) =>
            {
                int bothSucceeded = 0;
                int neitherSucceeded = 0;
                for (int round = 0; round < 200; round++)
                {
                    using EphemeralEcdh ours = EphemeralEcdh.Generate();
                    using EphemeralEcdh first = EphemeralEcdh.Generate();
                    using EphemeralEcdh second = EphemeralEcdh.Generate();
                    byte[] firstKey = first.PublicKeySpki;
                    byte[] secondKey = second.PublicKeySpki;
                    using Barrier barrier = new Barrier(2);
                    Task<bool> a = Task.Run(() => TryAgree(ours, firstKey, barrier));
                    Task<bool> b = Task.Run(() => TryAgree(ours, secondKey, barrier));
                    int succeeded = (a.GetAwaiter().GetResult() ? 1 : 0) + (b.GetAwaiter().GetResult() ? 1 : 0);
                    bothSucceeded += succeeded == 2 ? 1 : 0;
                    neitherSucceeded += succeeded == 0 ? 1 : 0;
                }
                return new RaceOutcome(bothSucceeded, neitherSucceeded);
            })
        .TheTest
        .ShouldPass<RaceOutcome>((because, _, outcome) =>
        {
            because.ItsTrue($"no round agreed twice ({outcome.BothSucceeded})", outcome.BothSucceeded == 0);
            because.ItsTrue($"every round agreed once ({outcome.NeitherSucceeded} agreed none)", outcome.NeitherSucceeded == 0);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void NeverDeriveFromAClearedSecretWhenDisposeRaces()
    {
        When.A<string>("races DeriveKey against Dispose on one agreement, 2000 times",
            "derive race",
            (_) =>
            {
                byte[] salt = SHA256.HashData(Encoding.UTF8.GetBytes("transcript"));
                byte[] zeroKey = KeyDerivation.Hkdf(new byte[EphemeralEcdh.SecretLength], salt, ClientToServerLabel, 32);
                int real = 0;
                int disposed = 0;
                int wrong = 0;
                for (int round = 0; round < 2000; round++)
                {
                    using EphemeralEcdh client = EphemeralEcdh.Generate();
                    using EphemeralEcdh server = EphemeralEcdh.Generate();
                    using EcdhAgreement reference = server.Agree(client.PublicKeySpki).Agreement!;
                    byte[] expected = reference.DeriveKey(salt, ClientToServerLabel, 32);
                    EcdhAgreement agreement = client.Agree(server.PublicKeySpki).Agreement!;
                    using Barrier barrier = new Barrier(2);
                    Task<byte[]?> derive = Task.Run(() =>
                    {
                        barrier.SignalAndWait();
                        try
                        {
                            return agreement.DeriveKey(salt, ClientToServerLabel, 32);
                        }
                        catch (ObjectDisposedException)
                        {
                            return null;
                        }
                    });
                    Task dispose = Task.Run(() =>
                    {
                        barrier.SignalAndWait();
                        agreement.Dispose();
                    });
                    byte[]? derived = derive.GetAwaiter().GetResult();
                    dispose.GetAwaiter().GetResult();
                    if (derived == null)
                    {
                        disposed++;
                    }
                    else if (derived.SequenceEqual(expected))
                    {
                        real++;
                    }
                    else
                    {
                        wrong++;
                    }
                    if (derived != null && derived.SequenceEqual(zeroKey))
                    {
                        wrong++;
                    }
                }
                return new DeriveRaceOutcome(real, disposed, wrong);
            })
        .TheTest
        .ShouldPass<DeriveRaceOutcome>((because, _, outcome) =>
        {
            because.ItsTrue($"every derivation gave the real key or ObjectDisposedException ({outcome.Real} real, {outcome.Disposed} disposed, {outcome.Wrong} wrong)", outcome.Wrong == 0);
            because.ItsTrue("all 2000 rounds ended one of those two ways", outcome.Real + outcome.Disposed == 2000);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void GiveTheClaimBackWhenAgreeRacesDispose()
    {
        When.A<string>("races Agree against Dispose on one key pair, 500 times",
            "agree race",
            (_) =>
            {
                int unexpected = 0;
                int succeededOrDisposed = 0;
                for (int round = 0; round < 500; round++)
                {
                    EphemeralEcdh ours = EphemeralEcdh.Generate();
                    using EphemeralEcdh peer = EphemeralEcdh.Generate();
                    byte[] peerKey = peer.PublicKeySpki;
                    using Barrier barrier = new Barrier(2);
                    Task<string> agree = Task.Run(() =>
                    {
                        barrier.SignalAndWait();
                        try
                        {
                            EcdhAgreementResult result = ours.Agree(peerKey);
                            result.Agreement?.Dispose();
                            return result.Succeeded ? "agreed" : "refused:" + result.Reason;
                        }
                        catch (ObjectDisposedException)
                        {
                            return "disposed";
                        }
                    });
                    Task dispose = Task.Run(() =>
                    {
                        barrier.SignalAndWait();
                        ours.Dispose();
                    });
                    string outcome = agree.GetAwaiter().GetResult();
                    dispose.GetAwaiter().GetResult();
                    // Whatever happened, a disposed pair must say so rather than claim to be in use.
                    bool disposedAfterwards = Throws<ObjectDisposedException>(() => ours.Agree(peerKey));
                    if ((outcome == "agreed" || outcome == "disposed" || outcome.StartsWith("refused:", StringComparison.Ordinal)) && disposedAfterwards)
                    {
                        succeededOrDisposed++;
                    }
                    else
                    {
                        unexpected++;
                    }
                }
                return new AgreeRaceOutcome(succeededOrDisposed, unexpected);
            })
        .TheTest
        .ShouldPass<AgreeRaceOutcome>((because, _, outcome) =>
        {
            because.ItsTrue($"each race ended in an agreement, a refusal or ObjectDisposedException, and the pair then reported itself disposed ({outcome.Unexpected} unexpected)", outcome.Unexpected == 0 && outcome.Expected == 500);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void RefuseUseAfterDisposeAndListTheSessionTags()
    {
        When.A<string>("disposes each primitive and uses it, and checks the tag list",
            "dispose",
            (_) =>
            {
                AeadKey key = AeadKey.Generate();
                SequenceNonce.TryCreate(FrameDirection.ClientToServer, 0, out byte[] nonce);
                byte[] sealedData = key.Seal(nonce, new byte[] { 1 }, Array.Empty<byte>());
                key.Dispose();
                key.Dispose();
                EphemeralEcdh pair = EphemeralEcdh.Generate();
                using EphemeralEcdh peer = EphemeralEcdh.Generate();
                pair.Dispose();
                pair.Dispose();
                return new DisposeOutcome(
                    Throws<ObjectDisposedException>(() => key.Seal(nonce, new byte[] { 1 }, Array.Empty<byte>())),
                    Throws<ObjectDisposedException>(() => key.Open(nonce, sealedData, Array.Empty<byte>())),
                    Throws<ObjectDisposedException>(() => pair.Agree(peer.PublicKeySpki)),
                    TaggedPayload.Tags.Contains(TaggedPayload.SessionTranscript),
                    TaggedPayload.Build(TaggedPayload.SealedFrame, "x").Error?.Category);
            })
        .TheTest
        .ShouldPass<DisposeOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("a disposed AeadKey refuses to seal", outcome.SealAfterDispose);
            because.ItsTrue("a disposed AeadKey refuses to open", outcome.OpenAfterDispose);
            because.ItsTrue("a disposed key pair refuses to agree", outcome.AgreeAfterDispose);
            because.ItsTrue("the session transcript tag can be built", outcome.TranscriptListed);
            because.ItsTrue("the sealed-frame label is never built as a signed payload", outcome.SealedFrameRefused == DeviceKeyErrorCategory.InvalidRequest);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    [UnitTest]
    public void AgreeOnTheSameKeysFromBothEnds()
    {
        When.A<string>("runs a key agreement between two generated key pairs and passes a frame each way",
            "both ends",
            (_) =>
            {
                using EphemeralEcdh client = EphemeralEcdh.Generate();
                using EphemeralEcdh server = EphemeralEcdh.Generate();
                byte[] salt = SHA256.HashData(Encoding.UTF8.GetBytes("transcript"));
                using EcdhAgreement clientAgreement = client.Agree(server.PublicKeySpki).Agreement!;
                using EcdhAgreement serverAgreement = server.Agree(client.PublicKeySpki).Agreement!;
                using AeadKey clientSends = clientAgreement.DeriveAeadKey(salt, ClientToServerLabel);
                using AeadKey serverReceives = serverAgreement.DeriveAeadKey(salt, ClientToServerLabel);
                using AeadKey serverSends = serverAgreement.DeriveAeadKey(salt, ServerToClientLabel);
                SequenceNonce.TryCreate(FrameDirection.ClientToServer, 0, out byte[] requestNonce);
                SequenceNonce.TryCreate(FrameDirection.ServerToClient, 0, out byte[] answerNonce);
                byte[] request = clientSends.Seal(requestNonce, Encoding.UTF8.GetBytes("request"), Array.Empty<byte>());
                byte[] answer = serverSends.Seal(answerNonce, Encoding.UTF8.GetBytes("answer"), Array.Empty<byte>());
                using AeadKey clientReceives = clientAgreement.DeriveAeadKey(salt, ServerToClientLabel);
                return new BothEndsOutcome(
                    CanonicalSpki.Canonicalize(client.PublicKeySpki).Value!.SequenceEqual(client.PublicKeySpki),
                    Encoding.UTF8.GetString(serverReceives.Open(requestNonce, request, Array.Empty<byte>()).Plaintext ?? Array.Empty<byte>()),
                    Encoding.UTF8.GetString(clientReceives.Open(answerNonce, answer, Array.Empty<byte>()).Plaintext ?? Array.Empty<byte>()),
                    serverSends.Open(requestNonce, request, Array.Empty<byte>()).Status);
            })
        .TheTest
        .ShouldPass<BothEndsOutcome>((because, _, outcome) =>
        {
            because.ItsTrue("the public key is already in canonical form", outcome.PublicKeyCanonical);
            because.ItsTrue("the server opens the client's frame", outcome.Request == "request");
            because.ItsTrue("the client opens the server's frame", outcome.Answer == "answer");
            because.ItsTrue("a request frame does not open with the answer key", outcome.ReflectedStatus == AeadOpenStatus.Tampered);
        })
        .SoBeHappy()
        .UnlessItFailed();
    }

    private static T ReadVectors<T>(string fileName)
    {
        string path = Path.Combine(AppContext.BaseDirectory, "TestData", "sealed-frames", fileName);
        return JsonSerializer.Deserialize<T>(File.ReadAllText(path), JsonOptions)
            ?? throw new InvalidOperationException($"{path} is empty.");
    }

    private static byte[] Range(int start, int count)
    {
        return Enumerable.Range(start, count).Select(value => (byte)value).ToArray();
    }

    private static bool Throws<TException>(Action action) where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }

    private static bool TryAgree(EphemeralEcdh pair, byte[] peerKey, Barrier barrier)
    {
        barrier.SignalAndWait();
        try
        {
            EcdhAgreementResult result = pair.Agree(peerKey);
            result.Agreement?.Dispose();
            return result.Succeeded;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    private static bool HexEquals(byte[] bytes, string hex) => Convert.ToHexString(bytes).Equals(hex, StringComparison.OrdinalIgnoreCase);

    private sealed record HkdfOutcome(string Case1, string Case2);

    private sealed record SessionVectors(List<SessionVector> Cases, List<RefusedSessionVector> Refused);

    private sealed record RefusedSessionVector(string Name, string ServerPublicKey);

    private sealed record CanonicalOutcome(List<bool> Refused, bool RefusalsExplained, bool NonCanonicalNamed, bool AgreedAfterRefusals, bool PublicKeyIsACopy);

    private sealed record RaceOutcome(int BothSucceeded, int NeitherSucceeded);

    private sealed record DeriveRaceOutcome(int Real, int Disposed, int Wrong);

    private sealed record AgreeRaceOutcome(int Expected, int Unexpected);

    private sealed record DisposeOutcome(bool SealAfterDispose, bool OpenAfterDispose, bool AgreeAfterDispose, bool TranscriptListed, DeviceKeyErrorCategory? SealedFrameRefused);

    private sealed record SessionVector(
        string Name,
        string Audience,
        string ActorKeyFingerprint,
        string SessionId,
        string ClientPrivateScalarHex,
        string ClientPublicKey,
        string ServerPrivateScalarHex,
        string ServerPublicKey,
        long Expires,
        string TranscriptUtf8Hex,
        string SharedHex,
        string SaltHex,
        string KeyClientToServerHex,
        string KeyServerToClientHex);

    private sealed record SessionCaseOutcome(
        string Name,
        bool ClientKeyMatches,
        bool ServerKeyMatches,
        bool TranscriptMatches,
        bool SaltMatches,
        bool HkdfFromSharedMatches,
        bool ClientKeysMatch,
        bool ServerKeysMatch,
        bool SharedStartsWithZero)
    {
        public static SessionCaseOutcome For(SessionVector vector)
        {
            using EphemeralEcdh client = EphemeralEcdh.FromPrivateScalar(Convert.FromHexString(vector.ClientPrivateScalarHex));
            using EphemeralEcdh server = EphemeralEcdh.FromPrivateScalar(Convert.FromHexString(vector.ServerPrivateScalarHex));
            byte[] transcript = TaggedPayload.Build(TaggedPayload.SessionTranscript,
                vector.Audience, vector.ActorKeyFingerprint, vector.SessionId, vector.ClientPublicKey, vector.ServerPublicKey,
                vector.Expires.ToString(System.Globalization.CultureInfo.InvariantCulture)).Value!;
            byte[] salt = SHA256.HashData(transcript);
            byte[] shared = Convert.FromHexString(vector.SharedHex);
            using EcdhAgreement clientAgreement = client.Agree(vector.ServerPublicKey.FromBase64UrlEncoded()).Agreement!;
            using EcdhAgreement serverAgreement = server.Agree(vector.ClientPublicKey.FromBase64UrlEncoded()).Agreement!;
            return new SessionCaseOutcome(
                vector.Name,
                client.PublicKeySpki.SequenceEqual(vector.ClientPublicKey.FromBase64UrlEncoded()),
                server.PublicKeySpki.SequenceEqual(vector.ServerPublicKey.FromBase64UrlEncoded()),
                HexEquals(transcript, vector.TranscriptUtf8Hex),
                HexEquals(salt, vector.SaltHex),
                HexEquals(KeyDerivation.Hkdf(shared, salt, ClientToServerLabel, 32), vector.KeyClientToServerHex)
                    && HexEquals(KeyDerivation.Hkdf(shared, salt, ServerToClientLabel, 32), vector.KeyServerToClientHex),
                HexEquals(clientAgreement.DeriveKey(salt, ClientToServerLabel, 32), vector.KeyClientToServerHex)
                    && HexEquals(clientAgreement.DeriveKey(salt, ServerToClientLabel, 32), vector.KeyServerToClientHex),
                HexEquals(serverAgreement.DeriveKey(salt, ClientToServerLabel, 32), vector.KeyClientToServerHex)
                    && HexEquals(serverAgreement.DeriveKey(salt, ServerToClientLabel, 32), vector.KeyServerToClientHex),
                shared.Length == 32 && shared[0] == 0);
        }
    }

    private sealed record FrameVectors(string KeyClientToServerHex, string KeyServerToClientHex, ulong MaximumFramesPerDirection, List<FrameVector> Frames);

    private sealed record FrameVector(string Name, string Direction, ulong Sequence, string PlaintextHex, string NonceHex, string AssociatedData, string Ciphertext);

    private sealed record FrameOutcome(string Name, bool NonceMatches, bool SealMatches, bool OpenMatches);

    private sealed record FrameSetOutcome(ulong MaximumFramesPerDirection, List<FrameOutcome> Frames);

    private sealed record OpenOutcome(
        List<AeadOpenStatus> Tampered,
        List<AeadOpenStatus> Malformed,
        bool RefusalsCarryNoPlaintext,
        bool Opened,
        bool LengthIsPlaintextPlusTag,
        bool EmptyPlaintextRoundTrips);

    private sealed record NonceOutcome(
        string First,
        string Answer,
        string Last,
        bool AtLimit,
        int AtLimitLength,
        bool Wrapped,
        bool CustomLimit,
        bool ZeroLimit,
        bool UnknownDirection,
        bool ZeroDirection);

    private sealed record RefusalOutcome(
        bool EmptyInfo,
        bool BlankLabel,
        bool InvalidLabel,
        bool EmptySalt,
        bool EmptySecret,
        bool LengthOutOfRange,
        bool MaximumLength,
        bool LabelsSeparateKeys,
        bool WrongKeyLength,
        bool WrongNonceLength,
        bool OtherCurveRefused,
        bool GarbageRefused,
        bool AgreedAfterRefusals,
        bool SecondAgreeThrows,
        bool DisposedAgreementThrows,
        bool ScalarOutOfRange);

    private sealed record BothEndsOutcome(bool PublicKeyCanonical, string Request, string Answer, AeadOpenStatus ReflectedStatus);
}

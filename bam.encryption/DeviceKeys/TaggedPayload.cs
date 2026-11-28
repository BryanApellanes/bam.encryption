using System.Security.Cryptography;
using System.Text;

namespace Bam.Encryption.DeviceKeys;

/// <summary>
/// Builds the payloads device keys and host keys sign. A key never signs bytes another party chose: it signs a
/// payload built from fields it can show or check, beginning with a tag that names what the signature is for, so a
/// signature for one purpose can never be replayed as another.
/// </summary>
/// <remarks>
/// Format: UTF-8, the tag first, then one field per line, separated by <c>\n</c>, with no trailing newline (the
/// format bam.protocol's <c>CanonicalRequest</c> uses). Fields are used exactly as given, never re-formatted, and
/// may not contain control characters, which would make the line framing ambiguous.
/// </remarks>
public static class TaggedPayload
{
    /// <summary>Approving a device under a signed-in session (native apps).</summary>
    public const string DeviceKey = "BAM-DEVICE-KEY-1";

    /// <summary>Completing a pairing.</summary>
    public const string DevicePair = "BAM-DEVICE-PAIR-1";

    /// <summary>Renewing a device link.</summary>
    public const string DeviceRenew = "BAM-DEVICE-RENEW-1";

    /// <summary>A sealed-frame session's transcript (bam.protocol#118), which the host signs with its key. It names
    /// the audience, the actor key's fingerprint, the session id, both ephemeral public keys and the expiry.</summary>
    public const string SessionTranscript = "BAM-SESSION-TRANSCRIPT-1";

    /// <summary>An account key chain entry (threeheadz-tracker#45, bam.protocol#103): account id, seq, prev, op and
    /// its fields, then the signer, each as a <c>key:value</c> line.</summary>
    public const string AccountKey = "BAM-ACCOUNT-KEY-1";

    /// <summary>A signed profile projection (threeheadz-tracker#45): account id, domain, version, and the SHA-256 of the
    /// projection.</summary>
    public const string Profile = "BAM-PROFILE-1";

    /// <summary>The sealed-frame label (bam.protocol#118): the prefix of a frame's associated data and of its key
    /// derivation labels. Listed so no signed tag collides with it; it is never signed, so <see cref="Build"/>
    /// refuses it.</summary>
    public const string SealedFrame = "BAM-SEALED-FRAME-1";

    /// <summary>The per-request proof (bam.protocol's <c>CanonicalRequest</c>), listed so no device tag collides with
    /// it. Device keys build it through bam.protocol, not here.</summary>
    public const string RequestProof = "BAM-REQUEST-PROOF-1";

    private static readonly IReadOnlyList<string> SignedTags = Array.AsReadOnly(new[] { DeviceKey, DevicePair, DeviceRenew, SessionTranscript, AccountKey, Profile });

    /// <summary>
    /// The tags <see cref="Build"/> accepts.
    /// </summary>
    public static IReadOnlyList<string> Tags => SignedTags;

    /// <summary>
    /// Builds a payload.
    /// </summary>
    /// <param name="tag">One of <see cref="Tags"/>.</param>
    /// <param name="fields">The fields, in the order the payload's definition lists them.</param>
    /// <returns>The payload's bytes, or <see cref="DeviceKeyErrorCategory.InvalidRequest"/> for an unknown tag, a null
    /// field, a field with a control character, or a field that is not valid UTF-16 (a lone surrogate).</returns>
    public static DeviceKeyResult<byte[]> Build(string tag, params string[] fields)
    {
        if (tag == null || !SignedTags.Contains(tag, StringComparer.Ordinal))
        {
            return DeviceKeyResult<byte[]>.Failure(DeviceKeyErrorCategory.InvalidRequest, $"Unknown payload tag '{tag}'.");
        }
        if (fields == null || fields.Length == 0)
        {
            return DeviceKeyResult<byte[]>.Failure(DeviceKeyErrorCategory.InvalidRequest, "A payload needs at least one field.");
        }
        for (int index = 0; index < fields.Length; index++)
        {
            string field = fields[index];
            if (field == null)
            {
                return DeviceKeyResult<byte[]>.Failure(DeviceKeyErrorCategory.InvalidRequest, $"Field {index + 1} is null.");
            }
            if (field.Any(char.IsControl))
            {
                return DeviceKeyResult<byte[]>.Failure(DeviceKeyErrorCategory.InvalidRequest, $"Field {index + 1} contains a control character.");
            }
            if (HasLoneSurrogate(field))
            {
                return DeviceKeyResult<byte[]>.Failure(DeviceKeyErrorCategory.InvalidRequest, $"Field {index + 1} is not valid text (a lone surrogate).");
            }
        }
        string text = tag + "\n" + string.Join("\n", fields);
        return DeviceKeyResult<byte[]>.Success(new UTF8Encoding(false, true).GetBytes(text));
    }

    /// <summary>
    /// The WebAuthn challenge for a payload: base64url of its SHA-256, so a passkey assertion commits to the same
    /// fields the device key signed. A client compares the challenge it was given with this before prompting.
    /// </summary>
    /// <param name="payload">The payload's bytes.</param>
    /// <returns>The challenge.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="payload"/> is null.</exception>
    public static string ChallengeFor(byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        return SHA256.HashData(payload).ToBase64UrlEncoded();
    }

    private static bool HasLoneSurrogate(string field)
    {
        for (int i = 0; i < field.Length; i++)
        {
            if (char.IsHighSurrogate(field[i]) && i + 1 < field.Length && char.IsLowSurrogate(field[i + 1]))
            {
                i++;
            }
            else if (char.IsSurrogate(field[i]))
            {
                return true;
            }
        }
        return false;
    }
}

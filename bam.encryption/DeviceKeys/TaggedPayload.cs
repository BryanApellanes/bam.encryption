using System.Security.Cryptography;
using System.Text;

namespace Bam.Encryption.DeviceKeys;

/// <summary>
/// Builds the payloads device keys sign. A device key never signs bytes a server chose: it signs a payload it builds
/// itself from fields it can show or check, beginning with a tag that names what the signature is for, so a
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

    /// <summary>The per-request proof (bam.protocol's <c>CanonicalRequest</c>), listed so no device tag collides with
    /// it. Device keys build it through bam.protocol, not here.</summary>
    public const string RequestProof = "BAM-REQUEST-PROOF-1";

    private static readonly IReadOnlyList<string> DeviceTags = new[] { DeviceKey, DevicePair, DeviceRenew };

    /// <summary>
    /// The tags <see cref="Build"/> accepts.
    /// </summary>
    public static IReadOnlyList<string> Tags => DeviceTags;

    /// <summary>
    /// Builds a payload.
    /// </summary>
    /// <param name="tag">One of <see cref="Tags"/>.</param>
    /// <param name="fields">The fields, in the order the payload's definition lists them.</param>
    /// <returns>The payload's bytes, or <see cref="DeviceKeyErrorCategory.InvalidRequest"/> for an unknown tag, a null
    /// field, or a field with a control character.</returns>
    public static DeviceKeyResult<byte[]> Build(string tag, params string[] fields)
    {
        if (tag == null || !DeviceTags.Contains(tag, StringComparer.Ordinal))
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
    public static string ChallengeFor(byte[] payload)
    {
        return SHA256.HashData(payload).ToBase64UrlEncoded();
    }
}

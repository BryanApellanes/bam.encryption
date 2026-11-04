namespace Bam.Encryption.Tests.TestClasses;

/// <summary>
/// Test fixture that turns hex vectors (RFC 8949 appendix A style) into bytes.
/// </summary>
public sealed class CborVectors
{
    public byte[] Hex(string hex)
    {
        return Convert.FromHexString(hex);
    }
}

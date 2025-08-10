using Org.BouncyCastle.Security;

namespace Bam.Encryption;

public class HmacKeyProvider : IHmacKeyProvider
{
    Dictionary<string, byte[]> _hmacKeys = new Dictionary<string, byte[]>();
    public HmacKeyProvider()
    {
        this.PersistNamedHmacKeys = true;
        this.Key = GetNewHmacKey();
    }
    public bool PersistNamedHmacKeys { get; set; }
    public byte[] Key { get; set; }
    
    public byte[] GetNewHmacKey()
    {
        byte[] result = new byte[32];
        SecureRandom r = new SecureRandom();
        r.NextBytes(result);
        return result;
    }

    public byte[] GetNamedHmacKey(string name)
    {
        string fileName = $"hmac_key-{name}";
        if (BamProfile.TryReadVaultDotSysFile(fileName, out string content))
        {
            _hmacKeys[name] = content.FromBase64();
        }
        if (!_hmacKeys.ContainsKey(name))
        {
            _hmacKeys.Add(name, GetNewHmacKey());
        }
        
        byte[] hmacKey = _hmacKeys[name];
        if (PersistNamedHmacKeys)
        {
            BamProfile.WriteVaultDotSysFile(fileName, hmacKey.ToBase64());
        }
        return hmacKey;
    }
}
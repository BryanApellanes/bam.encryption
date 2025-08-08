using Org.BouncyCastle.Security;

namespace Bam.Encryption;

public class HmacKeyProvider : IHmacKeyProvider
{
    Dictionary<string, byte[]> _hmacKeys = new Dictionary<string, byte[]>();
    public HmacKeyProvider()
    {
        this.Key = GetNewHmacKey();
    }
    
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
        if (!_hmacKeys.ContainsKey(name))
        {
            _hmacKeys.Add(name, GetNewHmacKey());
        }
        
        return _hmacKeys[name];
    }
}
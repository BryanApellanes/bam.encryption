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

    /// <summary>
    /// Retrieves the HMAC key associated with the specified name, creating and persisting a new key if one does not
    /// already exist.
    /// </summary>
    /// <remarks>If the key does not exist, a new HMAC key is generated and optionally persisted based on the
    /// value of the PersistNamedHmacKeys property. The same key will be returned for subsequent calls with the same
    /// name, unless the underlying storage is modified.</remarks>
    /// <param name="name">The unique name identifying the HMAC key to retrieve. Cannot be null.</param>
    /// <returns>A byte array containing the HMAC key associated with the specified name. If no key exists for the given name, a
    /// new key is generated and returned.</returns>
    public byte[] GetNamedHmacKey(string name)
    {
        bool newKey = false;
        string fileName = $"hmac_key-{name}";
        if (BamProfile.TryReadVaultDotSysFileBytes(fileName, out byte[]? content))
        {
            if(content == null)
            {
                content = GetNewHmacKey();
                newKey = true;
            }
            _hmacKeys[name] = content;
        }
        if (!_hmacKeys.ContainsKey(name))
        {
            _hmacKeys.Add(name, GetNewHmacKey());
            newKey = true;
        }
        
        byte[] hmacKey = _hmacKeys[name];
        if (PersistNamedHmacKeys && newKey)
        {
            BamProfile.WriteVaultDotSysFile(fileName, hmacKey);
        }
        return hmacKey;
    }
}
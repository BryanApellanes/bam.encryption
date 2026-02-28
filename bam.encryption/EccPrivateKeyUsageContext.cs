namespace Bam.Encryption;

public class EccPrivateKeyUsageContext : ProtectedKeyUsageContext
{
    byte[] _privateKeyCipher;
    bool _disposed = false;
    AesKey _aesKey;

    public EccPrivateKeyUsageContext(byte[] privateKeyBytes)
    {
        _aesKey = new AesKey();
        _privateKeyCipher = _aesKey.EncryptBytes(privateKeyBytes);
    }

    public override void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public override void UseKey(Action<IPrivateKey> action)
    {
        byte[] privateKeyBytes = _aesKey.DecryptBytes(_privateKeyCipher);
        using (EccPublicPrivateKeyPair keyPair = new EccPublicPrivateKeyPair(privateKeyBytes))
        {
            action(new EccPrivateKey(keyPair));
        }
    }

    public ISignature SignWithKey(string data)
    {
        ISignature? result = null;
        UseKey(privateKey => result = privateKey.Sign(data));
        return result!;
    }

    public ISignature SignWithKey(byte[] data)
    {
        ISignature? result = null;
        UseKey(privateKey => result = privateKey.Sign(data));
        return result!;
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;
        if (disposing)
        {
            Array.Clear(_privateKeyCipher, 0, _privateKeyCipher.Length);
        }
        _disposed = true;
    }
}

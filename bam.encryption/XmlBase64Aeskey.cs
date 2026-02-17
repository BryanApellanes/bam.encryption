using System.Text;

namespace Bam.Encryption;

/// <summary>
/// An AES key that supports XML Base64 file serialization. Use <see cref="AesKey"/> instead.
/// </summary>
[Obsolete("Use AesKey instead")]
public class XmlBase64Aeskey : AesKey
{
    static readonly object _aesLock = new object();
    static volatile XmlBase64Aeskey _key = null!;
    /// <summary>
    /// Gets the advanced encryption key vector pair for the currently running bam system.
    /// </summary>
    [Obsolete("Use AesKey.SystemKey instead")]
    public new static AesKey SystemKey
    {
        get
        {
            if (_key == null)
            {
                lock(_aesLock)
                {
                    string fileName = Path.Combine(BamHome.Local, SystemKeyFileName);
                    if (File.Exists(fileName))
                    {
                        _key = LoadXmlBase64(fileName);
                    }
                    else
                    {
                        _key = new XmlBase64Aeskey();
                        _key.SaveXmlBase64(fileName);
                    }
                }
            }

            return _key;
        }
    }
    
    /// <summary>
    /// Saves this AES key to the specified file path as XML encoded in Base64.
    /// </summary>
    /// <param name="filePath">The file path to save the key to.</param>
    public void SaveXmlBase64(string filePath)
    {
        FileInfo fileInfo = new FileInfo(filePath);
        if (fileInfo.Directory != null && !fileInfo.Directory.Exists)
        {
            fileInfo.Directory.Create();
        }
        string xml = this.ToXml();
        byte[] xmlBytes = Encoding.UTF8.GetBytes(xml);
        string xmlBase64 = Convert.ToBase64String(xmlBytes);
        using StreamWriter sw = new StreamWriter(filePath);
        sw.Write(xmlBase64);
    }
    
    /// <summary>
    /// Loads an AES key from the specified XML Base64-encoded file.
    /// </summary>
    /// <param name="filePath">The file path to load the key from.</param>
    /// <returns>The deserialized AES key.</returns>
    public static XmlBase64Aeskey LoadXmlBase64(string filePath)
    {
        using (StreamReader sr = new StreamReader(filePath))
        {
            string xmlBase64 = sr.ReadToEnd();
            byte[] xmlBytes = Convert.FromBase64String(xmlBase64);
            string xml = Encoding.UTF8.GetString(xmlBytes);
            return xml.FromXml<XmlBase64Aeskey>();
        }
    }
}
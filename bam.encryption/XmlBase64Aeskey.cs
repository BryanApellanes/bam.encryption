using System.Text;

namespace Bam.Encryption;

[Obsolete("Use AesKey instead")]
public class XmlBase64Aeskey : AesKey
{
    static readonly object _aesLock = new object();
    static volatile XmlBase64Aeskey _key;
    /// <summary>
    /// Gets the advanced encryption key vector pair for the currently running bam system.
    /// </summary>
    [Obsolete("Use AesKey.SystemKey instead")]
    public static AesKey SystemKey
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
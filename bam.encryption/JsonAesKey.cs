
using Bam;
using Bam.Encryption;

public class JsonAesKey : AesKey
{
    public void SaveJson(string filePath)
    {
        this.ToJsonFile(new FileInfo(filePath));
    }

    public static AesKey LoadJson(string filePath)
    {
        return filePath.FromJsonFile<AesKey>();
    }
}
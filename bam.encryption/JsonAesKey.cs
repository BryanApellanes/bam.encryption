
using Bam;
using Bam.Encryption;

/// <summary>
/// An AES key that supports JSON file serialization and deserialization.
/// </summary>
public class JsonAesKey : AesKey
{
    /// <summary>
    /// Saves this AES key to the specified file path in JSON format.
    /// </summary>
    /// <param name="filePath">The file path to save the key to.</param>
    public void SaveJson(string filePath)
    {
        this.ToJsonFile(new FileInfo(filePath));
    }

    /// <summary>
    /// Loads an AES key from the specified JSON file.
    /// </summary>
    /// <param name="filePath">The file path to load the key from.</param>
    /// <returns>The deserialized AES key.</returns>
    public static AesKey LoadJson(string filePath)
    {
        return filePath.FromJsonFile<AesKey>();
    }
}
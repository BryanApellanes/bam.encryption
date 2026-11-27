namespace Bam.Encryption;

/// <summary>
/// An <see cref="INamedKeyStorage"/> that keeps each named key as one file under a directory, so a
/// host's keys survive a restart. The bytes are stored as given: the files are protected by file
/// permissions, not by encryption. On Unix the directory is created mode 0700 and every file,
/// including the temporary file a write goes through, mode 0600, so other local users cannot read
/// the keys. On Windows the directory inherits its parent's ACL; put it under a user profile or a
/// secret volume.
/// </summary>
/// <remarks>
/// A key is stored as <c>&lt;name&gt;.pem</c> with every character that is not valid in a file
/// name replaced by an underscore. Two names that differ only in such characters share a file.
/// </remarks>
public sealed class FileNamedKeyStorage : INamedKeyStorage
{
    /// <summary>Owner read, write and execute: the mode of the key directory on Unix.</summary>
    public const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    /// <summary>Owner read and write: the mode of every key file on Unix.</summary>
    public const UnixFileMode KeyFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private const string KeyFileExtension = ".pem";
    private const string TemporaryExtension = ".tmp";

    /// <summary>Creates the directory at <paramref name="rootPath"/> if needed, and uses it.</summary>
    /// <param name="rootPath">The key directory.</param>
    /// <exception cref="ArgumentException"><paramref name="rootPath"/> is null or blank.</exception>
    public FileNamedKeyStorage(string rootPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        RootPath = Path.GetFullPath(rootPath);
        CreatePrivateDirectory(RootPath);
    }

    /// <summary>The absolute path of the key directory.</summary>
    public string RootPath { get; }

    /// <inheritdoc />
    /// <remarks>
    /// The bytes are written to a temporary file that is then moved over the key file, so a reader
    /// never sees a partly written key.
    /// </remarks>
    public bool SaveNamedKey(string keyName, byte[] keyBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentNullException.ThrowIfNull(keyBytes);
        string path = PathFor(keyName);
        string temporary = path + TemporaryExtension;
        FileStreamOptions options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = KeyFileMode;
        }

        using (FileStream stream = new FileStream(temporary, options))
        {
            stream.Write(keyBytes);
        }

        if (!OperatingSystem.IsWindows())
        {
            // UnixCreateMode applies only when the file is created, and is masked by the umask. A
            // temporary file left by an interrupted write keeps whatever mode it had.
            File.SetUnixFileMode(temporary, KeyFileMode);
        }

        File.Move(temporary, path, overwrite: true);
        return true;
    }

    /// <inheritdoc />
    public byte[]? GetNamedKey(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        string path = PathFor(name);
        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    /// <summary>
    /// Creates a directory that only its owner can read on Unix, and tightens one that already
    /// exists. On Windows it creates the directory and leaves its ACL as inherited.
    /// </summary>
    /// <param name="path">The directory.</param>
    /// <exception cref="ArgumentException"><paramref name="path"/> is null or blank.</exception>
    public static void CreatePrivateDirectory(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (OperatingSystem.IsWindows())
        {
            Directory.CreateDirectory(path);
            return;
        }

        Directory.CreateDirectory(path, DirectoryMode);
        File.SetUnixFileMode(path, DirectoryMode);
    }

    private string PathFor(string keyName)
    {
        // The separators are replaced on every platform. Path.GetInvalidFileNameChars leaves the
        // backslash alone on Unix, and a name must give the same file wherever the directory is read.
        string fileName = keyName.Replace('/', '_').Replace('\\', '_');
        foreach (char invalid in Path.GetInvalidFileNameChars())
        {
            fileName = fileName.Replace(invalid, '_');
        }

        return Path.Combine(RootPath, fileName + KeyFileExtension);
    }
}

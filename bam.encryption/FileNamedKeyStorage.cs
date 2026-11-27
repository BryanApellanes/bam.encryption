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
/// <para>
/// A key is stored as <c>&lt;name&gt;.pem</c> with every character in
/// <see cref="ReplacedCharacters"/>, and every control character, replaced by an underscore. The
/// set is the same on every platform, so a name gives the same file wherever the directory is
/// read. Two names that differ only in replaced characters share a file, and so do two names that
/// differ only in case on a file system that ignores case. Use names the host controls.
/// </para>
/// <para>
/// An existing directory is trusted as found. Its mode is tightened on Unix, but a key file that
/// is already there is read as the host's key. Use a directory, under a parent, that no other
/// user could write to before the host first ran.
/// </para>
/// </remarks>
public sealed class FileNamedKeyStorage : INamedKeyStorage
{
    /// <summary>Owner read, write and execute: the mode of the key directory on Unix.</summary>
    public const UnixFileMode DirectoryMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    /// <summary>Owner read and write: the mode of every key file on Unix.</summary>
    public const UnixFileMode KeyFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    /// <summary>
    /// The printable characters replaced by an underscore in a key's file name, on every platform:
    /// both path separators and the characters Windows does not allow in a file name.
    /// </summary>
    public const string ReplacedCharacters = "/\\:*?\"<>|";

    private const string KeyFileExtension = ".pem";
    private const string TemporaryExtension = ".tmp";
    private const int MoveAttempts = 50;
    private const int MoveRetryDelayMilliseconds = 10;

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
    /// The bytes are written and flushed to a new, uniquely named temporary file that is then
    /// moved over the key file, so a reader never sees a partly written key and two saves of one
    /// name do not write into each other. The last move wins. The temporary file is created only
    /// if no file of that name exists, so a file or link planted under its name is never written
    /// through. When the save fails the temporary file is deleted and the key file is left as it
    /// was.
    /// <para>
    /// On Windows the key file cannot be replaced while anything has it open. The save waits for a
    /// gap, for under a second, and then throws. A host that reads one key from several threads
    /// without pause can make a save of that key fail there; read the key once and keep it, or
    /// try the save again.
    /// </para>
    /// </remarks>
    /// <exception cref="UnauthorizedAccessException">
    /// On Windows, the key file stayed open elsewhere for as long as the save kept trying.
    /// </exception>
    /// <exception cref="IOException">The key could not be written or moved into place.</exception>
    public bool SaveNamedKey(string keyName, byte[] keyBytes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentNullException.ThrowIfNull(keyBytes);
        string path = PathFor(keyName);
        string temporary = path + "." + Guid.NewGuid().ToString("N") + TemporaryExtension;
        FileStreamOptions options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = KeyFileMode;
        }

        bool moved = false;
        try
        {
            using (FileStream stream = new FileStream(temporary, options))
            {
                if (!OperatingSystem.IsWindows())
                {
                    // UnixCreateMode is masked by the umask, so the mode is set again, before any
                    // key byte is written.
                    File.SetUnixFileMode(stream.SafeFileHandle, KeyFileMode);
                }

                stream.Write(keyBytes);
                stream.Flush(flushToDisk: true);
            }

            MoveIntoPlace(temporary, path);
            moved = true;
            return true;
        }
        finally
        {
            if (!moved)
            {
                File.Delete(temporary);
            }
        }
    }

    /// <inheritdoc />
    public byte[]? GetNamedKey(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        string path = PathFor(name);
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                // Shares everything, so this read never makes another reader's open fail. It does
                // not help a save on Windows: a move over a file that anyone has open is refused
                // there, whatever the reader shares.
                using FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using MemoryStream bytes = new MemoryStream();
                stream.CopyTo(bytes);
                return bytes.ToArray();
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (UnauthorizedAccessException) when (OperatingSystem.IsWindows() && attempt < MoveAttempts)
            {
                // Windows refuses to open a file in the instant a save is replacing it.
                Thread.Sleep(MoveRetryDelayMilliseconds);
            }
        }
    }

    /// <summary>
    /// Creates a directory that only its owner can read on Unix, and tightens the mode of one that
    /// already exists. What an existing directory holds is left as it is. On Windows it creates
    /// the directory and leaves its ACL as inherited.
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

    /// <summary>
    /// Moves the temporary file over the key file. On Windows a move over a file that anyone has
    /// open is refused, whatever that reader or writer shares, so the move needs an instant in
    /// which the key file is closed. It is tried again for under a second, and then the failure
    /// is let through.
    /// </summary>
    private static void MoveIntoPlace(string temporary, string path)
    {
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                File.Move(temporary, path, overwrite: true);
                return;
            }
            catch (Exception exception) when ((exception is IOException || exception is UnauthorizedAccessException) && attempt < MoveAttempts && File.Exists(temporary))
            {
                Thread.Sleep(MoveRetryDelayMilliseconds);
            }
        }
    }

    private string PathFor(string keyName)
    {
        char[] characters = keyName.ToCharArray();
        for (int index = 0; index < characters.Length; index++)
        {
            char character = characters[index];
            if (char.IsControl(character) || ReplacedCharacters.Contains(character))
            {
                characters[index] = '_';
            }
        }

        return Path.Combine(RootPath, new string(characters) + KeyFileExtension);
    }
}

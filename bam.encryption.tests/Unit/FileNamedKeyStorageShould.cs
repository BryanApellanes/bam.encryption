using System.Text;
using Bam.Console;
using Bam.Test;

namespace Bam.Encryption.Tests.Unit;

/// <summary>
/// Pins the directory-backed named key storage (bam.encryption#31): keys survive a new instance,
/// writes replace the file through a temporary one, names stay inside the root, and on Unix the
/// directory and files are readable by their owner only.
/// </summary>
[UnitTestMenu("File Named Key Storage Should", Selector = "fnks")]
public class FileNamedKeyStorageShould : UnitTestMenuContainer
{
    private static string NewRoot()
    {
        return Path.Combine(Path.GetTempPath(), "bam-fnks-" + Guid.NewGuid().ToString("N"));
    }

    private static void Remove(string root)
    {
        if (Directory.Exists(root))
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string? ArgumentFailure(Action action)
    {
        try
        {
            action();
            return null;
        }
        catch (ArgumentException exception)
        {
            return exception.GetType().Name;
        }
    }

    [UnitTest]
    public void ReadAKeyBackFromANewInstance()
    {
        When.A<FileNamedKeyStorageShould>("saves a key with one instance and reads it with another over the same directory", (test) =>
            {
                string root = NewRoot();
                try
                {
                    byte[] key = Encoding.UTF8.GetBytes("-----BEGIN TEST KEY-----\nabc\n-----END TEST KEY-----\n");
                    bool saved = new FileNamedKeyStorage(root).SaveNamedKey("server-signing", key);
                    FileNamedKeyStorage second = new FileNamedKeyStorage(root);
                    byte[]? read = second.GetNamedKey("server-signing");
                    return new RoundTripOutcome(saved, read != null && read.AsSpan().SequenceEqual(key), second.GetNamedKey("never-saved") == null, Path.IsPathFullyQualified(second.RootPath));
                }
                finally
                {
                    Remove(root);
                }
            })
            .TheTest
            .ShouldPass<RoundTripOutcome>((because, outcome) =>
            {
                because.ItsTrue("the save reports success", outcome.Saved);
                because.ItsTrue("a second instance reads the same bytes", outcome.SameBytes);
                because.ItsTrue("a name that was never saved reads as null", outcome.MissingIsNull);
                because.ItsTrue("the root path is absolute", outcome.RootIsAbsolute);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void ReplaceAKeyAndLeaveNoTemporaryFile()
    {
        When.A<FileNamedKeyStorageShould>("saves a name twice, the second time with shorter bytes", (test) =>
            {
                string root = NewRoot();
                try
                {
                    FileNamedKeyStorage storage = new FileNamedKeyStorage(root);
                    storage.SaveNamedKey("rotating", new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
                    storage.SaveNamedKey("rotating", new byte[] { 9, 9 });
                    storage.SaveNamedKey("empty", Array.Empty<byte>());
                    byte[]? read = storage.GetNamedKey("rotating");
                    byte[]? empty = storage.GetNamedKey("empty");
                    string[] files = Directory.GetFiles(root).Select(path => Path.GetFileName(path)).OrderBy(name => name, StringComparer.Ordinal).ToArray();
                    return new ReplaceOutcome(read != null && read.AsSpan().SequenceEqual(new byte[] { 9, 9 }), empty != null && empty.Length == 0, string.Join(",", files));
                }
                finally
                {
                    Remove(root);
                }
            })
            .TheTest
            .ShouldPass<ReplaceOutcome>((because, outcome) =>
            {
                because.ItsTrue("the second save replaced the first, with nothing left of the longer key", outcome.Replaced);
                because.ItsTrue("an empty key is stored and read as empty, not as missing", outcome.EmptyKept);
                because.ItsTrue("only the key files remain: " + outcome.Files, outcome.Files == "empty.pem,rotating.pem");
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void KeepEveryNameInsideTheRoot()
    {
        When.A<FileNamedKeyStorageShould>("saves names made of path separators and parent references", (test) =>
            {
                string parent = NewRoot();
                string root = Path.Combine(parent, "keys");
                try
                {
                    FileNamedKeyStorage storage = new FileNamedKeyStorage(root);
                    string[] names = new[] { "../escaped", "..\\escaped-too", "a/b", "/rooted", ".." };
                    bool allRead = true;
                    foreach (string name in names)
                    {
                        storage.SaveNamedKey(name, Encoding.UTF8.GetBytes(name));
                        byte[]? read = storage.GetNamedKey(name);
                        allRead = allRead && read != null && Encoding.UTF8.GetString(read) == name;
                    }

                    string[] outside = Directory.GetFileSystemEntries(parent).Select(path => Path.GetFileName(path)).ToArray();
                    string[] inside = Directory.GetFiles(root).Select(path => Path.GetFileName(path)).OrderBy(name => name, StringComparer.Ordinal).ToArray();
                    return new ContainmentOutcome(allRead, string.Join(",", outside), string.Join(",", inside), Directory.GetDirectories(root).Length);
                }
                finally
                {
                    Remove(parent);
                }
            })
            .TheTest
            .ShouldPass<ContainmentOutcome>((because, outcome) =>
            {
                because.ItsTrue("every name reads back", outcome.AllRead);
                because.ItsTrue("nothing was written beside the root: " + outcome.Outside, outcome.Outside == "keys");
                because.ItsTrue("the separators became underscores: " + outcome.Inside, outcome.Inside == "...pem,.._escaped-too.pem,.._escaped.pem,_rooted.pem,a_b.pem");
                because.ItsTrue("no directory was created under the root", outcome.DirectoriesInside == 0);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void RejectBlankRootsAndNames()
    {
        When.A<FileNamedKeyStorageShould>("is given a blank root, blank names and null bytes", (test) =>
            {
                string root = NewRoot();
                try
                {
                    FileNamedKeyStorage storage = new FileNamedKeyStorage(root);
                    return new RejectionOutcome(
                        ArgumentFailure(() => new FileNamedKeyStorage(" ")),
                        ArgumentFailure(() => storage.SaveNamedKey(" ", new byte[] { 1 })),
                        ArgumentFailure(() => storage.SaveNamedKey("name", null!)),
                        ArgumentFailure(() => storage.GetNamedKey(string.Empty)),
                        ArgumentFailure(() => FileNamedKeyStorage.CreatePrivateDirectory(string.Empty)),
                        Directory.GetFiles(root).Length);
                }
                finally
                {
                    Remove(root);
                }
            })
            .TheTest
            .ShouldPass<RejectionOutcome>((because, outcome) =>
            {
                because.ItsTrue("a blank root is rejected", outcome.BlankRoot == nameof(ArgumentException));
                because.ItsTrue("a blank name is rejected on save", outcome.BlankSaveName == nameof(ArgumentException));
                because.ItsTrue("null bytes are rejected", outcome.NullBytes == nameof(ArgumentNullException));
                because.ItsTrue("an empty name is rejected on read", outcome.EmptyReadName == nameof(ArgumentException));
                because.ItsTrue("an empty directory path is rejected", outcome.EmptyDirectory == nameof(ArgumentException));
                because.ItsTrue("nothing was written by the rejected calls", outcome.FilesWritten == 0);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void KeepKeysOwnerOnlyOnUnix()
    {
        When.A<FileNamedKeyStorageShould>("creates the directory and a key file, over a directory that was open to others", (test) =>
            {
                if (OperatingSystem.IsWindows())
                {
                    return new ModeOutcome(false, default, default, default);
                }

                string root = NewRoot();
                try
                {
                    Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
                    string staleTemporary = Path.Combine(root, "loose.pem.tmp");
                    File.WriteAllBytes(staleTemporary, new byte[] { 0 });
                    File.SetUnixFileMode(staleTemporary, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

                    FileNamedKeyStorage storage = new FileNamedKeyStorage(root);
                    storage.SaveNamedKey("fresh", new byte[] { 1 });
                    storage.SaveNamedKey("loose", new byte[] { 2 });
                    return new ModeOutcome(
                        true,
                        File.GetUnixFileMode(root),
                        File.GetUnixFileMode(Path.Combine(root, "fresh.pem")),
                        File.GetUnixFileMode(Path.Combine(root, "loose.pem")));
                }
                finally
                {
                    Remove(root);
                }
            })
            .TheTest
            .ShouldPass<ModeOutcome>((because, outcome) =>
            {
                if (!outcome.Checked)
                {
                    because.ItsTrue("file modes are a Unix concept, so nothing is checked on Windows", OperatingSystem.IsWindows());
                    return;
                }

                because.ItsTrue("an existing directory is tightened to 0700", outcome.Directory == FileNamedKeyStorage.DirectoryMode);
                because.ItsTrue("a new key file is 0600", outcome.FreshFile == FileNamedKeyStorage.KeyFileMode);
                because.ItsTrue("a key written over a loose temporary file is 0600", outcome.OverLooseTemporary == FileNamedKeyStorage.KeyFileMode);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    private sealed record RoundTripOutcome(bool Saved, bool SameBytes, bool MissingIsNull, bool RootIsAbsolute);

    private sealed record ReplaceOutcome(bool Replaced, bool EmptyKept, string Files);

    private sealed record ContainmentOutcome(bool AllRead, string Outside, string Inside, int DirectoriesInside);

    private sealed record RejectionOutcome(string? BlankRoot, string? BlankSaveName, string? NullBytes, string? EmptyReadName, string? EmptyDirectory, int FilesWritten);

    private sealed record ModeOutcome(bool Checked, UnixFileMode Directory, UnixFileMode FreshFile, UnixFileMode OverLooseTemporary);
}

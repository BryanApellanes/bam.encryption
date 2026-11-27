using System.Text;
using Bam.Console;
using Bam.Test;

namespace Bam.Encryption.Tests.Unit;

/// <summary>
/// Pins the directory-backed named key storage (bam.encryption#31): keys survive a new instance,
/// writes replace the file through a temporary one, concurrent saves leave every read whole, a
/// name gives the same file on every platform and stays inside the root, and on Unix the
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
    public void GiveANameTheSameFileOnEveryPlatform()
    {
        When.A<FileNamedKeyStorageShould>("saves names holding every replaced character and a control character", (test) =>
            {
                string root = NewRoot();
                try
                {
                    FileNamedKeyStorage storage = new FileNamedKeyStorage(root);
                    storage.SaveNamedKey("actor:server", new byte[] { 1 });
                    storage.SaveNamedKey("a*b?c\"d<e>f|g", new byte[] { 2 });
                    storage.SaveNamedKey("tab\there", new byte[] { 3 });
                    string[] files = Directory.GetFiles(root).Select(path => Path.GetFileName(path)).OrderBy(name => name, StringComparer.Ordinal).ToArray();
                    byte[]? read = storage.GetNamedKey("actor:server");
                    return new NamingOutcome(string.Join(",", files), read != null && read.Length == 1 && read[0] == 1, FileNamedKeyStorage.ReplacedCharacters);
                }
                finally
                {
                    Remove(root);
                }
            })
            .TheTest
            .ShouldPass<NamingOutcome>((because, outcome) =>
            {
                because.ItsTrue("each replaced character became an underscore: " + outcome.Files, outcome.Files == "a_b_c_d_e_f_g.pem,actor_server.pem,tab_here.pem");
                because.ItsTrue("the key reads back under its name", outcome.ReadBack);
                because.ItsTrue("the replaced set is the separators and the characters Windows refuses", outcome.Replaced == "/\\:*?\"<>|");
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void KeepEveryReadWholeWhileOneNameIsSavedFromManyThreads()
    {
        When.A<FileNamedKeyStorageShould>("saves one name from four threads while another thread reads it", (test) =>
            {
                string root = NewRoot();
                try
                {
                    const int KeyLength = 4096;
                    const int SavesPerWriter = 150;
                    FileNamedKeyStorage storage = new FileNamedKeyStorage(root);
                    storage.SaveNamedKey("shared", Enumerable.Repeat((byte)9, KeyLength).ToArray());
                    int failedSaves = 0;
                    int tornReads = 0;
                    int reads = 0;
                    string firstFailure = string.Empty;
                    using CancellationTokenSource writing = new CancellationTokenSource();
                    Task reader = Task.Run(() =>
                    {
                        while (!writing.IsCancellationRequested)
                        {
                            try
                            {
                                byte[]? key = new FileNamedKeyStorage(root).GetNamedKey("shared");
                                reads++;
                                if (key == null || key.Length != KeyLength || key.Any(value => value != key[0]))
                                {
                                    Interlocked.Increment(ref tornReads);
                                }
                            }
                            catch (Exception exception)
                            {
                                Interlocked.Increment(ref tornReads);
                                firstFailure = "read: " + exception.GetType().Name;
                            }
                        }
                    });
                    Task[] writers = Enumerable.Range(1, 4).Select(writer => Task.Run(() =>
                    {
                        byte[] key = Enumerable.Repeat((byte)writer, KeyLength).ToArray();
                        for (int save = 0; save < SavesPerWriter; save++)
                        {
                            try
                            {
                                storage.SaveNamedKey("shared", key);
                            }
                            catch (Exception exception)
                            {
                                Interlocked.Increment(ref failedSaves);
                                firstFailure = "save: " + exception.GetType().Name;
                            }
                        }
                    })).ToArray();
                    Task.WaitAll(writers);
                    writing.Cancel();
                    reader.Wait();
                    string[] files = Directory.GetFiles(root).Select(path => Path.GetFileName(path)).ToArray();
                    return new ConcurrencyOutcome(failedSaves, tornReads, reads, string.Join(",", files), firstFailure);
                }
                finally
                {
                    Remove(root);
                }
            })
            .TheTest
            .ShouldPass<ConcurrencyOutcome>((because, outcome) =>
            {
                because.ItsTrue("no save failed: " + outcome.FailedSaves + " " + outcome.FirstFailure, outcome.FailedSaves == 0);
                because.ItsTrue("the reader read at least once", outcome.Reads > 0);
                because.ItsTrue("every read was one whole key: " + outcome.TornReads + " " + outcome.FirstFailure, outcome.TornReads == 0);
                because.ItsTrue("no temporary file is left: " + outcome.Files, outcome.Files == "shared.pem");
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    public void LeaveNoTemporaryFileWhenASaveFails()
    {
        When.A<FileNamedKeyStorageShould>("saves a key whose file name is taken by a directory", (test) =>
            {
                string root = NewRoot();
                try
                {
                    FileNamedKeyStorage storage = new FileNamedKeyStorage(root);
                    Directory.CreateDirectory(Path.Combine(root, "blocked.pem"));
                    string thrown = string.Empty;
                    try
                    {
                        storage.SaveNamedKey("blocked", new byte[] { 1, 2, 3 });
                    }
                    catch (Exception exception) when (exception is IOException || exception is UnauthorizedAccessException)
                    {
                        thrown = exception.GetType().Name;
                    }

                    string[] entries = Directory.GetFileSystemEntries(root).Select(path => Path.GetFileName(path)).ToArray();
                    return new FailedSaveOutcome(thrown, string.Join(",", entries), Directory.Exists(Path.Combine(root, "blocked.pem")));
                }
                finally
                {
                    Remove(root);
                }
            })
            .TheTest
            .ShouldPass<FailedSaveOutcome>((because, outcome) =>
            {
                because.ItsTrue("the save threw: " + outcome.Thrown, outcome.Thrown.Length > 0);
                because.ItsTrue("the root holds only what was there before: " + outcome.Entries, outcome.Entries == "blocked.pem");
                because.ItsTrue("what was in the way is untouched", outcome.BlockerStillThere);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    public void KeepKeysOwnerOnlyOnUnix()
    {
        Skip.When(OperatingSystem.IsWindows(), "file modes are a Unix concept");

        When.A<FileNamedKeyStorageShould>("creates a key file, and replaces a loose one, in a directory that was open to others", (test) =>
            {
                string root = NewRoot();
                try
                {
                    UnixFileMode loose = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
                    Directory.CreateDirectory(root, loose | UnixFileMode.UserExecute);
                    string looseKey = Path.Combine(root, "loose.pem");
                    File.WriteAllBytes(looseKey, new byte[] { 0 });
                    File.SetUnixFileMode(looseKey, loose);

                    FileNamedKeyStorage storage = new FileNamedKeyStorage(root);
                    storage.SaveNamedKey("fresh", new byte[] { 1 });
                    storage.SaveNamedKey("loose", new byte[] { 2 });
                    return new ModeOutcome(File.GetUnixFileMode(root), File.GetUnixFileMode(Path.Combine(root, "fresh.pem")), File.GetUnixFileMode(looseKey));
                }
                finally
                {
                    Remove(root);
                }
            })
            .TheTest
            .ShouldPass<ModeOutcome>((because, outcome) =>
            {
                because.ItsTrue("an existing directory is tightened to 0700", outcome.Directory == FileNamedKeyStorage.DirectoryMode);
                because.ItsTrue("a new key file is 0600", outcome.FreshFile == FileNamedKeyStorage.KeyFileMode);
                because.ItsTrue("a key saved over a loose key file is 0600", outcome.OverLooseFile == FileNamedKeyStorage.KeyFileMode);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    [UnitTest]
    [System.Runtime.Versioning.UnsupportedOSPlatform("windows")]
    public void NotWriteThroughAPlantedTemporaryLinkOnUnix()
    {
        Skip.When(OperatingSystem.IsWindows(), "the planted link is a Unix symbolic link");

        When.A<FileNamedKeyStorageShould>("saves a key where the old fixed temporary name is a link to a file outside the directory", (test) =>
            {
                string parent = NewRoot();
                string root = Path.Combine(parent, "keys");
                try
                {
                    Directory.CreateDirectory(root);
                    string outside = Path.Combine(parent, "outside.txt");
                    File.WriteAllText(outside, "untouched");
                    File.CreateSymbolicLink(Path.Combine(root, "signing.pem.tmp"), outside);

                    FileNamedKeyStorage storage = new FileNamedKeyStorage(root);
                    storage.SaveNamedKey("signing", Encoding.UTF8.GetBytes("SECRETKEY"));
                    FileInfo keyFile = new FileInfo(Path.Combine(root, "signing.pem"));
                    byte[]? read = storage.GetNamedKey("signing");
                    return new PlantedLinkOutcome(File.ReadAllText(outside), keyFile.LinkTarget == null, read != null && Encoding.UTF8.GetString(read) == "SECRETKEY");
                }
                finally
                {
                    Remove(parent);
                }
            })
            .TheTest
            .ShouldPass<PlantedLinkOutcome>((because, outcome) =>
            {
                because.ItsTrue("the file outside the directory still holds what it held: " + outcome.OutsideText, outcome.OutsideText == "untouched");
                because.ItsTrue("the key file is a regular file, not a link", outcome.KeyFileIsRegular);
                because.ItsTrue("the key reads back", outcome.ReadBack);
            })
            .SoBeHappy()
            .UnlessItFailed();
    }

    private sealed record RoundTripOutcome(bool Saved, bool SameBytes, bool MissingIsNull, bool RootIsAbsolute);

    private sealed record ReplaceOutcome(bool Replaced, bool EmptyKept, string Files);

    private sealed record ContainmentOutcome(bool AllRead, string Outside, string Inside, int DirectoriesInside);

    private sealed record RejectionOutcome(string? BlankRoot, string? BlankSaveName, string? NullBytes, string? EmptyReadName, string? EmptyDirectory, int FilesWritten);

    private sealed record NamingOutcome(string Files, bool ReadBack, string Replaced);

    private sealed record ConcurrencyOutcome(int FailedSaves, int TornReads, int Reads, string Files, string FirstFailure);

    private sealed record FailedSaveOutcome(string Thrown, string Entries, bool BlockerStillThere);

    private sealed record ModeOutcome(UnixFileMode Directory, UnixFileMode FreshFile, UnixFileMode OverLooseFile);

    private sealed record PlantedLinkOutcome(string OutsideText, bool KeyFileIsRegular, bool ReadBack);
}

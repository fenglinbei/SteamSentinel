using System.IO;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static readonly object WorkerFixtureLock = new();
    private static readonly Dictionary<string, string> SharedWorkerFixtureRoots = new(StringComparer.OrdinalIgnoreCase);
    private static string? _suiteRoot;

    /// <summary>在共享或当前测试根目录下按需初始化一次运行时夹具目录，并复用不可变 Worker 夹具可执行文件。</summary>
    private static string EnsureSharedWorkerFixtureExecutable(string root, string mode)
    {
        string anchor = Path.GetFullPath(_suiteRoot ?? root);
        lock (WorkerFixtureLock)
        {
            if (!SharedWorkerFixtureRoots.TryGetValue(anchor, out string? fixtureDir) || !Directory.Exists(fixtureDir))
            {
                fixtureDir = Path.Combine(anchor, "_shared-worker-fixture-base");
                Directory.CreateDirectory(fixtureDir);
                foreach (string file in Directory.EnumerateFiles(AppContext.BaseDirectory))
                {
                    string destination = Path.Combine(fixtureDir, Path.GetFileName(file));
                    if (!File.Exists(destination)) File.Copy(file, destination, overwrite: false);
                }
                SharedWorkerFixtureRoots[anchor] = fixtureDir;
            }

            string path = Path.Combine(fixtureDir, "SteamSentinelFixture-" + mode + ".exe");
            if (!File.Exists(path))
            {
                File.Copy(Path.Combine(AppContext.BaseDirectory, "SteamSentinel.SelfTest.exe"), path, overwrite: false);
                File.Copy(Path.Combine(AppContext.BaseDirectory, "SteamSentinel.SelfTest.dll"), Path.ChangeExtension(path, ".dll"), overwrite: false);
            }

            return path;
        }
    }
}

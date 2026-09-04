#:property TargetFramework=net10.0-windows10.0.19041.0
#:property UseWPF=true
#:property PublishAot=false
#:property PublishTrimmed=false

#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Threading.Tasks;

// Run only the inert coverage regression against a chosen built or installed worker:
// dotnet run --file scripts/TestV0114CoverageWorker.cs -- <SelfTest.dll> <SteamSentinel.ArchiveWorker.exe>
// If a local NuGet feed is missing, pass -p:RestoreSources=https://api.nuget.org/v3/index.json before --.
// Requires .NET 10 SDK + Windows Desktop runtime. Does not execute SelfTest.Main or remediation tests.
internal static class CoverageWorkerSmoke
{
    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        if (args.Length != 2)
        {
            Console.Error.WriteLine("Usage: <SelfTest.dll> <SteamSentinel.ArchiveWorker.exe>");
            return 2;
        }
        string assemblyPath = Path.GetFullPath(args[0]), workerPath = Path.GetFullPath(args[1]);
        if (!File.Exists(assemblyPath) || !File.Exists(workerPath) || !File.Exists(Path.ChangeExtension(workerPath, ".dll")))
            throw new FileNotFoundException("SelfTest assembly and worker EXE/DLL must already exist.");
        string assemblyDirectory = Path.GetDirectoryName(assemblyPath)!;
        AssemblyLoadContext.Default.Resolving += (_, name) =>
        {
            string candidate = Path.Combine(assemblyDirectory, name.Name + ".dll");
            return File.Exists(candidate) ? AssemblyLoadContext.Default.LoadFromAssemblyPath(candidate) : null;
        };
        Assembly assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(assemblyPath);
        Type tests = assembly.GetType("SteamSentinel.SelfTest.Program", throwOnError: true)!;
        const BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;
        MethodInfo method = tests.GetMethod("TestV0114CoverageAsync", flags)
            ?? throw new MissingMethodException("Build v0.1.14 SelfTest with TestV0114CoverageAsync first.");
        FieldInfo failuresField = tests.GetField("Failures", flags)
            ?? throw new MissingFieldException("SelfTest failure collection is unavailable.");
        FieldInfo passedField = tests.GetField("_passed", flags)
            ?? throw new MissingFieldException("SelfTest pass counter is unavailable.");
        var failures = (IReadOnlyList<string>)failuresField.GetValue(null)!;
        int failedBefore = failures.Count, passedBefore = (int)passedField.GetValue(null)!;
        string fixturePrefix = Path.Combine(Path.GetFullPath(Path.GetTempPath()), "SteamSentinel-CoverageSmoke-");
        string root = fixturePrefix + Guid.NewGuid().ToString("N");
        Directory.CreateDirectory(root);
        const string variable = "STEAMSENTINEL_COVERAGE_WORKER_PATH";
        string? previous = Environment.GetEnvironmentVariable(variable);
        try
        {
            Environment.SetEnvironmentVariable(variable, workerPath);
            Console.WriteLine("COVERAGE_SMOKE_WORKER=" + workerPath);
            Console.WriteLine("COVERAGE_SMOKE_TESTS=" + assemblyPath);
            await (Task)method.Invoke(null, [root])!;
            int failed = failures.Count - failedBefore;
            int passed = (int)passedField.GetValue(null)! - passedBefore;
            Console.WriteLine($"COVERAGE_SMOKE_PASS={passed};FAIL={failed}");
            foreach (string failure in failures.Skip(failedBefore)) Console.Error.WriteLine("FAIL: " + failure);
            return failed == 0 ? 0 : 1;
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, previous);
            // Only the uniquely named inert fixture tree owned by this run may be removed.
            Type? validation = AssemblyLoadContext.Default.Assemblies.FirstOrDefault(a => a.GetName().Name == "SteamSentinel.Core")
                ?.GetType("SteamSentinel.Core.Utilities.Validation");
            bool unsafePath = validation is null || (bool)validation.GetMethod("ContainsReparsePoint")!.Invoke(null, [root])!;
            if (Path.GetFullPath(root).StartsWith(fixturePrefix, StringComparison.OrdinalIgnoreCase) && !unsafePath)
            {
                Directory.Delete(root, recursive: true);
                Console.WriteLine("Removed this run's inert coverage fixtures.");
            }
            else Console.Error.WriteLine("Fixture cleanup skipped, inspect: " + root);
        }
    }
}

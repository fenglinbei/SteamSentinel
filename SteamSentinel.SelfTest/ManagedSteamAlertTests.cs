using System.Diagnostics;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.WebSockets;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestManagedSteamAlertAsync(string root)
    {
        byte[] loader = ModFixture("renamed-plugin", native: true);
        byte[] host = HostFixture("renamed-component.bin", InnerFixture(true, true));
        static ManagedSteamAlertMatch Inspect(byte[] bytes)
        {
            using MemoryStream stream = new(bytes);
            return ManagedSteamAlertInspector.Inspect(stream, CancellationToken.None);
        }
        Check("Managed mod: renamed native downloader connected to IMod.Init", Inspect(loader) == ManagedSteamAlertMatch.ModDownloader);
        Check("Managed mod: rebuilt plugin using WebClient and Process.Start", Inspect(ModFixture("rebuilt-addon", false)) == ManagedSteamAlertMatch.ModDownloader);
        Check("Managed mod: downloader starts a different file", Inspect(ModFixture("other-target", false, samePath: false)) == ManagedSteamAlertMatch.None);
        Check("Managed mod: otherwise identical code unreachable from Init", Inspect(ModFixture("unreachable-helper", true, reachable: false)) == ManagedSteamAlertMatch.None);
        Check("Managed mod: normal update library without a mod lifecycle", Inspect(ModFixture("normal-updater", false, mod: false)) == ManagedSteamAlertMatch.None);
        Check("Managed mod: download without launching", Inspect(ModFixture("download-only", false, launch: false)) == ManagedSteamAlertMatch.None);
        Check("Managed host: renamed embedded resource with persistence and CDP", Inspect(host) == ManagedSteamAlertMatch.ResidentHost);
        Check("Managed host: ordinary dependency before the embedded core",
            Inspect(HostFixture("last.bin", InnerFixture(true, true), precedingResource: InnerFixture(false, true))) == ManagedSteamAlertMatch.ResidentHost);
        Check("Managed host: normal assembly bootstrap", Inspect(HostFixture("plain.bin", loader)) == ManagedSteamAlertMatch.None);
        Check("Managed host: CDP utility without Steam logon changes", Inspect(HostFixture("browser.bin", InnerFixture(false, true))) == ManagedSteamAlertMatch.None);
        Check("Managed host: startup utility without sending an evaluation", Inspect(HostFixture("startup.bin", InnerFixture(true, false))) == ManagedSteamAlertMatch.None);
        Check("Managed host: unreferenced embedded assembly", Inspect(HostFixture("other.bin", InnerFixture(true, true), false)) == ManagedSteamAlertMatch.None);
        Check("Managed core: standalone rebuilt component", Inspect(InnerFixture(true, true)) == ManagedSteamAlertMatch.SteamDebugCore);
        Check("Managed core: Steam startup alone", Inspect(InnerFixture(true, false)) == ManagedSteamAlertMatch.None);
        Check("Managed core: browser debugging alone", Inspect(InnerFixture(false, true)) == ManagedSteamAlertMatch.None);
        Check("Managed mod: truncated PE", Inspect(loader[..128]) == ManagedSteamAlertMatch.None);
        byte[] badToken = (byte[])loader.Clone();
        using (PEReader malformed = new(new MemoryStream(badToken)))
        {
            MetadataReader metadata = malformed.GetMetadataReader();
            MethodDefinition init = metadata.MethodDefinitions.Select(metadata.GetMethodDefinition)
                .Single(method => method.RelativeVirtualAddress != 0 && metadata.StringComparer.Equals(method.Name, "Init"));
            SectionHeader section = malformed.PEHeaders.SectionHeaders.Single(s => init.RelativeVirtualAddress >= s.VirtualAddress &&
                init.RelativeVirtualAddress < s.VirtualAddress + s.SizeOfRawData);
            int bodyOffset = section.PointerToRawData + init.RelativeVirtualAddress - section.VirtualAddress;
            int headerSize = (badToken[bodyOffset] & 3) == 2 ? 1 : (badToken[bodyOffset + 1] >> 4) * 4;
            Check("Managed mod: malformed fixture targets a real call operand", badToken[bodyOffset + headerSize] == OpCodes.Call.Value);
            BinaryPrimitives.WriteInt32LittleEndian(badToken.AsSpan(bodyOffset + headerSize + 1), int.MaxValue);
        }
        Check("Managed mod: malformed metadata token", Inspect(badToken) == ManagedSteamAlertMatch.None);
        using (MemoryStream cancelled = new(host))
        {
            bool stopped = false;
            try { ManagedSteamAlertInspector.Inspect(cancelled, new CancellationToken(true)); }
            catch (OperationCanceledException) { stopped = true; }
            Check("Managed mod: respects cancellation", stopped);
        }

        string folder = Path.Combine(root, "managed-mod-variants");
        Directory.CreateDirectory(folder);
        string dll = Path.Combine(folder, "cosmetic.dll"), exe = Path.Combine(folder, "desktop-helper.exe");
        string component = Path.Combine(folder, "renamed-plugin.dll");
        byte[] rebuiltCore = InnerFixture(true, true);
        await File.WriteAllBytesAsync(dll, loader);
        await File.WriteAllBytesAsync(exe, host);
        await File.WriteAllBytesAsync(component, rebuiltCore);
        string zip = Path.Combine(folder, "variant.zip");
        using (ZipArchive archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        {
            using (Stream member = archive.CreateEntry("new-name/feature.dll").Open()) member.Write(loader);
            using (Stream member = archive.CreateEntry("second/file.exe").Open()) member.Write(host);
            using (Stream member = archive.CreateEntry("third/library.dll").Open()) member.Write(rebuiltCore);
        }
        ScanReport report = await new ScanCoordinator().RunAsync(new ScanOptions
        {
            Mode = ScanMode.Custom,
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            InspectArchives = true,
            InspectDeepSignatures = false,
            CustomRoots = [folder]
        });
        foreach ((string path, string rule, string member) in new[]
        {
            (dll, "MANAGED-MOD-DOWNLOAD-LAUNCH", "feature.dll"), (exe, "MANAGED-STEAM-CEF-HOST", "file.exe"),
            (component, "MANAGED-STEAM-CEF-CORE", "library.dll")
        })
        {
            var found = report.Findings.Where(f => f.RuleId == rule).ToArray();
            Check("Managed mod: loose and ZIP member " + rule,
                found.Any(f => f.Target == path && f.TargetSha256 == f.Sha256) &&
                found.Any(f => f.Target == zip && f.ContentPath?.EndsWith(member, StringComparison.Ordinal) == true &&
                               f.TargetSha256 is not null && f.TargetSha256 != f.Sha256));
            Check("Managed mod: behavioral findings are review-only " + rule, found.Length >= 2 &&
                found.All(f => f is { IsKnownMalware: false, CanRemediate: false, Severity: FindingSeverity.High } &&
                    f.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly])));
        }
    }

    // Persist metadata only. A throwing type initializer guards all synthetic types, and no fixture is loaded.
    private sealed class ManagedModFixture(string name)
    {
        internal PersistedAssemblyBuilder Assembly { get; } = new(new AssemblyName(name), typeof(object).Assembly);
        internal ModuleBuilder Module => _module ??= Assembly.DefineDynamicModule(name);
        private ModuleBuilder? _module;
        internal TypeBuilder DefineGuardedType(string typeName)
        {
            TypeBuilder type = Module.DefineType(typeName, TypeAttributes.Public);
            ILGenerator guard = type.DefineTypeInitializer().GetILGenerator();
            guard.Emit(OpCodes.Newobj, typeof(NotSupportedException).GetConstructor(Type.EmptyTypes)!);
            guard.Emit(OpCodes.Throw);
            return type;
        }
        internal byte[] Emit(MethodBuilder? entry = null, string? resource = null, byte[]? payload = null, byte[]? precedingResource = null)
        {
            MetadataBuilder metadata = Assembly.GenerateMetadata(out BlobBuilder il, out BlobBuilder fields);
            BlobBuilder resources = new();
            if (resource is not null)
            {
                if (precedingResource is not null)
                {
                    metadata.AddManifestResource(ManifestResourceAttributes.Private, metadata.GetOrAddString("dependency.dll"), default, 0);
                    resources.WriteInt32(precedingResource.Length); resources.WriteBytes(precedingResource);
                    resources.Align(8);
                }
                metadata.AddManifestResource(ManifestResourceAttributes.Private, metadata.GetOrAddString(resource), default, (uint)resources.Count);
                resources.WriteInt32(payload!.Length);
                resources.WriteBytes(payload);
            }
            ManagedPEBuilder pe = new(entry is null ? PEHeaderBuilder.CreateLibraryHeader() : PEHeaderBuilder.CreateExecutableHeader(),
                new MetadataRootBuilder(metadata), il, fields, resources,
                entryPoint: entry is null ? default : (MethodDefinitionHandle)MetadataTokens.EntityHandle(entry.MetadataToken));
            BlobBuilder output = new();
            pe.Serialize(output);
            return output.ToArray();
        }
    }

    private static byte[] ModFixture(string name, bool native, bool samePath = true, bool reachable = true, bool mod = true, bool launch = true)
    {
        ManagedModFixture fixture = new(name);
        TypeBuilder type = fixture.DefineGuardedType("DifferentPlugin");
        if (mod)
        {
            TypeBuilder contract = fixture.Module.DefineType("Game.IMod", TypeAttributes.Interface | TypeAttributes.Abstract | TypeAttributes.Public);
            contract.DefineMethod("Init", MethodAttributes.Public | MethodAttributes.Abstract | MethodAttributes.Virtual, typeof(void), Type.EmptyTypes);
            type.AddInterfaceImplementation(contract.CreateType()!);
        }
        const MethodAttributes helper = MethodAttributes.Private | MethodAttributes.Static;
        MethodBuilder worker = type.DefineMethod("CheckContent", helper, typeof(void), Type.EmptyTypes);
        ILGenerator init = type.DefineMethod("Init", MethodAttributes.Public | MethodAttributes.Virtual, typeof(void), Type.EmptyTypes).GetILGenerator();
        if (reachable) init.Emit(OpCodes.Call, worker);
        init.Emit(OpCodes.Ret);
        ILGenerator body = worker.GetILGenerator();
        body.DeclareLocal(typeof(string));
        body.DeclareLocal(typeof(string));
        body.Emit(OpCodes.Ldc_I4_S, (sbyte)Environment.SpecialFolder.LocalApplicationData);
        body.Emit(OpCodes.Call, typeof(Environment).GetMethod("GetFolderPath", [typeof(Environment.SpecialFolder)])!);
        body.Emit(OpCodes.Ldstr, name + ".exe");
        body.Emit(OpCodes.Call, typeof(Path).GetMethod("Combine", [typeof(string), typeof(string)])!);
        body.Emit(OpCodes.Stloc_0);
        body.Emit(OpCodes.Ldnull);
        body.Emit(OpCodes.Ldstr, "https://" + name + ".invalid/fixture");
        body.Emit(OpCodes.Ldloc_0);
        if (native)
        {
            MethodBuilder fetch = type.DefinePInvokeMethod("CopyPayload", "urlmon.dll", "URLDownloadToFileW", helper | MethodAttributes.PinvokeImpl,
                CallingConventions.Standard, typeof(int), [typeof(object), typeof(string), typeof(string), typeof(int), typeof(object)], CallingConvention.Winapi, CharSet.Unicode);
            body.Emit(OpCodes.Ldc_I4_0); body.Emit(OpCodes.Ldnull); body.Emit(OpCodes.Call, fetch); body.Emit(OpCodes.Pop);
        }
        else body.Emit(OpCodes.Callvirt, typeof(WebClient).GetMethod("DownloadFile", [typeof(string), typeof(string)])!);
        if (launch)
        {
            if (native)
            {
                MethodBuilder run = type.DefinePInvokeMethod("OpenResult", "shell32.dll", "ShellExecuteW", helper | MethodAttributes.PinvokeImpl,
                    CallingConventions.Standard, typeof(nint), [typeof(object), typeof(string), typeof(string), typeof(string), typeof(string), typeof(int)],
                    CallingConvention.Winapi, CharSet.Unicode);
                body.Emit(OpCodes.Ldnull); body.Emit(OpCodes.Ldstr, "open"); body.Emit(samePath ? OpCodes.Ldloc_0 : OpCodes.Ldloc_1);
                body.Emit(OpCodes.Ldnull); body.Emit(OpCodes.Ldnull); body.Emit(OpCodes.Ldc_I4_0); body.Emit(OpCodes.Call, run);
            }
            else
            {
                body.Emit(samePath ? OpCodes.Ldloc_0 : OpCodes.Ldloc_1);
                body.Emit(OpCodes.Call, typeof(Process).GetMethod("Start", [typeof(string)])!);
            }
            body.Emit(OpCodes.Pop);
        }
        body.Emit(OpCodes.Ret); type.CreateType();
        return fixture.Emit();
    }

    private static byte[] InnerFixture(bool persistence, bool sends)
    {
        ManagedModFixture fixture = new("unrelated-resource-name");
        TypeBuilder type = fixture.DefineGuardedType("SyntheticCompanion");
        const MethodAttributes attr = MethodAttributes.Public | MethodAttributes.Static;
        ILGenerator config = type.DefineMethod("Configure", attr, typeof(void), Type.EmptyTypes).GetILGenerator();
        foreach (string value in new[] { @"Software\Microsoft\Windows\CurrentVersion\Run", "Steam", "-cef-enable-debugging" })
        { config.Emit(OpCodes.Ldstr, value); config.Emit(OpCodes.Pop); }
        if (persistence)
        {
            config.Emit(OpCodes.Ldnull); config.Emit(OpCodes.Ldnull); config.Emit(OpCodes.Ldnull);
            config.Emit(OpCodes.Callvirt, typeof(RegistryKey).GetMethod("SetValue", [typeof(string), typeof(object)])!);
        }
        config.Emit(OpCodes.Ret);
        ILGenerator socket = type.DefineMethod("InspectPage", attr, typeof(void), Type.EmptyTypes).GetILGenerator();
        socket.Emit(OpCodes.Ldstr, "Runtime.evaluate"); socket.Emit(OpCodes.Pop);
        socket.DeclareLocal(typeof(CancellationToken)); socket.DeclareLocal(typeof(ArraySegment<byte>));
        socket.Emit(OpCodes.Ldnull); socket.Emit(OpCodes.Ldnull); socket.Emit(OpCodes.Ldloc_0);
        socket.Emit(OpCodes.Callvirt, typeof(ClientWebSocket).GetMethod("ConnectAsync", [typeof(Uri), typeof(CancellationToken)])!); socket.Emit(OpCodes.Pop);
        if (sends)
        {
            socket.Emit(OpCodes.Ldnull); socket.Emit(OpCodes.Ldloc_1); socket.Emit(OpCodes.Ldc_I4_0); socket.Emit(OpCodes.Ldc_I4_1); socket.Emit(OpCodes.Ldloc_0);
            socket.Emit(OpCodes.Callvirt, typeof(WebSocket).GetMethod("SendAsync", [typeof(ArraySegment<byte>), typeof(WebSocketMessageType), typeof(bool), typeof(CancellationToken)])!);
            socket.Emit(OpCodes.Pop);
        }
        socket.Emit(OpCodes.Ret); type.CreateType();
        return fixture.Emit();
    }

    private static byte[] HostFixture(string resourceName, byte[] payload, bool referenceResource = true, byte[]? precedingResource = null)
    {
        ManagedModFixture fixture = new("safe-resource-host");
        TypeBuilder type = fixture.DefineGuardedType("TestHost");
        MethodBuilder entry = type.DefineMethod("Main", MethodAttributes.Static | MethodAttributes.Public, typeof(void), Type.EmptyTypes);
        ILGenerator body = entry.GetILGenerator();
        if (precedingResource is not null)
        {
            body.Emit(OpCodes.Ldnull); body.Emit(OpCodes.Ldstr, "dependency.dll");
            body.Emit(OpCodes.Callvirt, typeof(Assembly).GetMethod("GetManifestResourceStream", [typeof(string)])!); body.Emit(OpCodes.Pop);
        }
        body.Emit(OpCodes.Ldnull); body.Emit(OpCodes.Ldstr, referenceResource ? resourceName : "absent-resource.dll");
        body.Emit(OpCodes.Callvirt, typeof(Assembly).GetMethod("GetManifestResourceStream", [typeof(string)])!); body.Emit(OpCodes.Pop);
        body.Emit(OpCodes.Ldnull); body.Emit(OpCodes.Call, typeof(Assembly).GetMethod("Load", [typeof(byte[])])!); body.Emit(OpCodes.Pop);
        body.Emit(OpCodes.Ldnull); body.Emit(OpCodes.Ldnull); body.Emit(OpCodes.Ldnull);
        body.Emit(OpCodes.Callvirt, typeof(MethodBase).GetMethod("Invoke", [typeof(object), typeof(object[])])!); body.Emit(OpCodes.Pop);
        body.Emit(OpCodes.Ret); type.CreateType();
        return fixture.Emit(entry, resourceName, payload, precedingResource);
    }
}

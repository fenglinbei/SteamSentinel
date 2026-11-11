using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;

namespace SteamSentinel.Core.Inspection;

internal enum ManagedSteamAlertMatch { None, ModDownloader, ResidentHost, SteamDebugCore }

/// <summary>Reads ECMA-335 metadata and IL. Never resolves an assembly, invokes a method, or follows a URL.</summary>
internal static class ManagedSteamAlertInspector
{
    private const int MaximumMetadata = 2 * 1024 * 1024;
    private const int MaximumResource = 4 * 1024 * 1024;
    private const int MaximumMethodIl = 64 * 1024;
    private const int MaximumTotalIl = 2 * 1024 * 1024;
    private static readonly Dictionary<short, OpCode> Opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(field => field.FieldType == typeof(OpCode)).Select(field => (OpCode)field.GetValue(null)!).ToDictionary(op => op.Value);

    internal static ManagedSteamAlertMatch Inspect(Stream stream, CancellationToken token)
    {
        long start = stream.Position;
        try
        {
            token.ThrowIfCancellationRequested();
            // Preserve the shared scan read budget. PEReader seeks to metadata and relevant RVA ranges on demand.
            if (stream.Length > 8 * 1024 * 1024 || stream.Length < 128) return ManagedSteamAlertMatch.None;
            stream.Position = 0;
            using PEReader pe = new(stream, PEStreamOptions.LeaveOpen);
            if (!Eligible(pe)) return ManagedSteamAlertMatch.None;
            Image image = new(pe, token);
            if (image.HasModDownloader()) return ManagedSteamAlertMatch.ModDownloader;
            if (image.HasResidentHost()) return ManagedSteamAlertMatch.ResidentHost;
            return image.HasSteamDebugPersistence() ? ManagedSteamAlertMatch.SteamDebugCore : ManagedSteamAlertMatch.None;
        }
        catch (Exception error) when (InvalidMetadata(error))
        {
            return ManagedSteamAlertMatch.None;
        }
        finally { stream.Position = start; }
    }

    private static bool Eligible(PEReader pe) =>
        pe.PEHeaders.CorHeader is { MetadataDirectory.Size: > 0 and <= MaximumMetadata } && pe.HasMetadata;

    private static bool InvalidMetadata(Exception error) =>
        error is BadImageFormatException or ArgumentException or InvalidOperationException or OverflowException;

    private sealed class Image(PEReader pe, CancellationToken token)
    {
        private readonly MetadataReader _metadata = pe.GetMetadataReader(MetadataReaderOptions.None);
        private int _ilBytes;

        internal bool HasModDownloader()
        {
            if (_metadata.TypeDefinitions.Count > 4096 || _metadata.MethodDefinitions.Count > 8192 ||
                _metadata.GetTableRowCount(TableIndex.InterfaceImpl) is 0 or > 8192) return false;
            Queue<MethodDefinitionHandle> pending = new();
            foreach (TypeDefinitionHandle handle in _metadata.TypeDefinitions)
            {
                token.ThrowIfCancellationRequested();
                TypeDefinition type = _metadata.GetTypeDefinition(handle);
                if (!type.GetInterfaceImplementations().Any(i => IsMod(_metadata.GetInterfaceImplementation(i).Interface))) continue;
                foreach (MethodDefinitionHandle method in type.GetMethods())
                    if (_metadata.StringComparer.Equals(_metadata.GetMethodDefinition(method).Name, "Init")) pending.Enqueue(method);
            }
            HashSet<MethodDefinitionHandle> seen = [];
            while (pending.TryDequeue(out MethodDefinitionHandle method) && seen.Count < 128)
            {
                if (!seen.Add(method)) continue;
                Facts facts = ReadMethod(method);
                if (facts.LaunchesDownload) return true;
                foreach (MethodDefinitionHandle callee in facts.Calls)
                    if (!seen.Contains(callee) && pending.Count < 512) pending.Enqueue(callee);
            }
            return false;
        }

        private bool IsMod(EntityHandle type) => type.Kind switch
        {
            HandleKind.TypeReference => _metadata.StringComparer.Equals(_metadata.GetTypeReference((TypeReferenceHandle)type).Name, "IMod"),
            HandleKind.TypeDefinition => _metadata.StringComparer.Equals(_metadata.GetTypeDefinition((TypeDefinitionHandle)type).Name, "IMod"),
            _ => false
        };

        internal bool HasResidentHost()
        {
            CorHeader cor = pe.PEHeaders.CorHeader!;
            if (cor.Flags.HasFlag(CorFlags.NativeEntryPoint) || cor.EntryPointTokenOrRelativeVirtualAddress == 0 ||
                _metadata.ManifestResources.Count is 0 or > 128) return false;
            EntityHandle entry = MetadataTokens.EntityHandle(cor.EntryPointTokenOrRelativeVirtualAddress);
            if (entry.Kind != HandleKind.MethodDefinition) return false;
            Facts main = ReadMethod((MethodDefinitionHandle)entry);
            if (!main.LoadsAssembly || !main.InvokesMethod || main.ResourceNames.Count == 0) return false;
            DirectoryEntry directory = cor.ResourcesDirectory;
            if (directory.Size < 4 || directory.Size > 8 * 1024 * 1024) return false;
            PEMemoryBlock block = pe.GetSectionData(directory.RelativeVirtualAddress);
            int remaining = MaximumResource;
            int examined = 0;
            foreach (ManifestResourceHandle handle in _metadata.ManifestResources)
            {
                token.ThrowIfCancellationRequested();
                ManifestResource resource = _metadata.GetManifestResource(handle);
                if (!resource.Implementation.IsNil || !main.ResourceNames.Any(name => _metadata.StringComparer.Equals(resource.Name, name)) ||
                    resource.Offset < 0 || resource.Offset > Math.Min(directory.Size, block.Length) - 4) continue;
                int offset = (int)resource.Offset;
                BlobReader size = block.GetReader(offset, 4);
                int length = size.ReadInt32();
                if (length < 128 || length > remaining || length > Math.Min(directory.Size, block.Length) - offset - 4) continue;
                BlobReader data = block.GetReader(offset + 4, length);
                if (data.ReadUInt16() != 0x5a4d) continue;
                // Only names used by the entry point are inspected, sharing one byte limit across nested images.
                remaining -= length;
                if (++examined > 4) break;
                try
                {
                    using PEReader embedded = new(block.GetContent(offset + 4, length));
                    if (Eligible(embedded) && new Image(embedded, token).HasSteamDebugPersistence()) return true;
                }
                catch (Exception error) when (InvalidMetadata(error)) { /* Continue with other referenced resources. */ }
            }
            return false;
        }

        internal bool HasSteamDebugPersistence()
        {
            if (_metadata.MethodDefinitions.Count > 4096 || !ReferencesRegistryAndWebSockets()) return false;
            bool registersSteamDebug = false, sendsEvaluation = false;
            foreach (MethodDefinitionHandle method in _metadata.MethodDefinitions)
            {
                Facts facts = ReadMethod(method);
                registersSteamDebug |= facts.RunKey && facts.SetRegistryValue && facts.Steam && facts.CefFlag;
                sendsEvaluation |= facts.Evaluate && facts.ConnectSocket && facts.SendSocket;
                if (registersSteamDebug && sendsEvaluation) return true;
                if (_ilBytes >= MaximumTotalIl) break;
            }
            return false;
        }

        private bool ReferencesRegistryAndWebSockets()
        {
            if (_metadata.MemberReferences.Count > 8192) return false;
            bool registry = false, socket = false;
            foreach (MemberReferenceHandle handle in _metadata.MemberReferences)
            {
                token.ThrowIfCancellationRequested();
                MemberReference member = _metadata.GetMemberReference(handle);
                if (member.Parent.Kind != HandleKind.TypeReference) continue;
                if (_metadata.StringComparer.Equals(member.Name, "SetValue"))
                {
                    TypeReference type = _metadata.GetTypeReference((TypeReferenceHandle)member.Parent);
                    registry |= _metadata.StringComparer.Equals(type.Namespace, "Microsoft.Win32") && _metadata.StringComparer.Equals(type.Name, "RegistryKey");
                }
                if (_metadata.StringComparer.Equals(member.Name, "ConnectAsync"))
                {
                    TypeReference type = _metadata.GetTypeReference((TypeReferenceHandle)member.Parent);
                    socket |= _metadata.StringComparer.Equals(type.Namespace, "System.Net.WebSockets") && _metadata.StringComparer.Equals(type.Name, "ClientWebSocket");
                }
                if (registry && socket) return true;
            }
            return false;
        }

        private Facts ReadMethod(MethodDefinitionHandle handle)
        {
            token.ThrowIfCancellationRequested();
            Facts facts = new();
            MethodDefinition method = _metadata.GetMethodDefinition(handle);
            if (method.RelativeVirtualAddress == 0 || (method.ImplAttributes & MethodImplAttributes.CodeTypeMask) != MethodImplAttributes.IL)
                return facts;
            BlobReader il = pe.GetMethodBody(method.RelativeVirtualAddress).GetILReader();
            if (il.Length > MaximumMethodIl || il.Length > MaximumTotalIl - _ilBytes) return facts;
            _ilBytes += il.Length;
            Instruction[] last = new Instruction[6];
            int count = 0;
            while (il.RemainingBytes > 0)
            {
                if ((count & 127) == 0) token.ThrowIfCancellationRequested();
                int code = il.ReadByte();
                if (code == 0xfe) code = 0xfe00 | il.ReadByte();
                if (!Opcodes.TryGetValue(unchecked((short)code), out OpCode op)) throw new BadImageFormatException();
                int operand = ReadOperand(ref il, op.OperandType);
                string? literal = op.Value == OpCodes.Ldstr.Value ? UserString(operand) : null;
                Instruction Previous(int n) => count < n ? default : last[(count - n) % last.Length];
                Instruction current = new(code, operand, literal);
                if (literal != null)
                {
                    facts.RunKey |= literal.Equals(@"Software\Microsoft\Windows\CurrentVersion\Run", StringComparison.OrdinalIgnoreCase);
                    facts.CefFlag |= literal.Contains("-cef-enable-debugging", StringComparison.OrdinalIgnoreCase);
                    facts.Steam |= literal.Equals("Steam", StringComparison.OrdinalIgnoreCase) || literal.EndsWith(@"\steam.exe", StringComparison.OrdinalIgnoreCase);
                    facts.Evaluate |= literal.Contains("Runtime.evaluate", StringComparison.Ordinal);
                }
                if (code is 0x28 or 0x6f or 0x73 or 0xfe06 or 0xfe07)
                {
                    EntityHandle target = MetadataTokens.EntityHandle(operand);
                    if (target.Kind == HandleKind.MethodSpecification) target = _metadata.GetMethodSpecification((MethodSpecificationHandle)target).Method;
                    if (target.Kind == HandleKind.MethodDefinition)
                    {
                        MethodDefinitionHandle definition = (MethodDefinitionHandle)target;
                        if (facts.Calls.Count < 128) facts.Calls.Add(definition);
                        if (code is 0x28 or 0x6f)
                        {
                            MethodImport import = _metadata.GetMethodDefinition(definition).GetImport();
                            if (!import.Module.IsNil)
                            {
                                StringHandle module = _metadata.GetModuleReference(import.Module).Name;
                                if (NativeApi(module, import.Name, "urlmon", "URLDownloadToFile") && Previous(4).RemoteUrl &&
                                    Previous(3).LoadLocal is int download && facts.Executables.Contains(download)) facts.Downloaded.Add(download);
                                if (NativeApi(module, import.Name, "shell32", "ShellExecute") && Previous(4).LoadLocal is int launch &&
                                    facts.Downloaded.Contains(launch)) facts.LaunchesDownload = true;
                            }
                        }
                    }
                    else if (target.Kind == HandleKind.MemberReference && code is 0x28 or 0x6f)
                    {
                        MemberReference member = _metadata.GetMemberReference((MemberReferenceHandle)target);
                        if (member.Parent.Kind == HandleKind.TypeReference)
                        {
                            TypeReference owner = _metadata.GetTypeReference((TypeReferenceHandle)member.Parent);
                            bool Api(string ns, string type, string name) => _metadata.StringComparer.Equals(owner.Namespace, ns) &&
                                _metadata.StringComparer.Equals(owner.Name, type) && _metadata.StringComparer.Equals(member.Name, name);
                            current.ProfilePath = Api("System", "Environment", "GetFolderPath") && Previous(1) is { Code: 0x1f or 0x20, Operand: 26 or 28 };
                            if (Api("System.IO", "Path", "Combine") && Previous(1).Literal is string leaf && !Path.IsPathRooted(leaf) &&
                                !leaf.Split('\\', '/').Contains("..", StringComparer.Ordinal))
                            {
                                current.ProfilePath = Previous(2).ProfilePath || Previous(2).LoadLocal is int local && facts.ProfilePaths.Contains(local);
                                current.Executable = current.ProfilePath && leaf.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
                            }
                            if (Api("System.Net", "WebClient", "DownloadFile") && Previous(2).RemoteUrl &&
                                Previous(1).LoadLocal is int download && facts.Executables.Contains(download)) facts.Downloaded.Add(download);
                            if (Api("System.Diagnostics", "Process", "Start") && IsStaticSingleArgument(member) &&
                                Previous(1).LoadLocal is int launch && facts.Downloaded.Contains(launch))
                                facts.LaunchesDownload = true;
                            if (Api("System.Reflection", "Assembly", "GetManifestResourceStream") && Previous(1).Literal is string name && facts.ResourceNames.Count < 8)
                                facts.ResourceNames.Add(name);
                            facts.LoadsAssembly |= facts.ResourceNames.Count != 0 && Api("System.Reflection", "Assembly", "Load");
                            facts.InvokesMethod |= facts.LoadsAssembly && (Api("System.Reflection", "MethodBase", "Invoke") || Api("System.Reflection", "MethodInfo", "Invoke"));
                            facts.SetRegistryValue |= Api("Microsoft.Win32", "RegistryKey", "SetValue");
                            facts.ConnectSocket |= Api("System.Net.WebSockets", "ClientWebSocket", "ConnectAsync");
                            facts.SendSocket |= Api("System.Net.WebSockets", "WebSocket", "SendAsync") || Api("System.Net.WebSockets", "ClientWebSocket", "SendAsync");
                        }
                    }
                }
                if (current.StoreLocal is int slot)
                {
                    facts.Downloaded.Remove(slot);
                    if (Previous(1).ProfilePath) facts.ProfilePaths.Add(slot);
                    else facts.ProfilePaths.Remove(slot);
                    if (Previous(1).Executable) facts.Executables.Add(slot);
                    else facts.Executables.Remove(slot);
                }
                last[count++ % last.Length] = current;
            }
            return facts;
        }

        private bool NativeApi(StringHandle module, StringHandle entry, string dll, string name) =>
            (_metadata.StringComparer.Equals(module, dll, ignoreCase: true) || _metadata.StringComparer.Equals(module, dll + ".dll", ignoreCase: true)) &&
            (_metadata.StringComparer.Equals(entry, name + "W") || _metadata.StringComparer.Equals(entry, name + "A") || _metadata.StringComparer.Equals(entry, name));

        private bool IsStaticSingleArgument(MemberReference member)
        {
            BlobReader signature = _metadata.GetBlobReader(member.Signature);
            SignatureHeader header = signature.ReadSignatureHeader();
            return header.Kind == SignatureKind.Method && !header.IsInstance && !header.IsGeneric && signature.ReadCompressedInteger() == 1;
        }

        // Avoid expanding a large #US blob into a string merely to compare a short command or resource name.
        private string? UserString(int operand)
        {
            if ((uint)operand >> 24 != 0x70) throw new BadImageFormatException();
            int offset = operand & 0xffffff;
            int size = _metadata.GetHeapSize(HeapIndex.UserString);
            if (offset >= size) throw new BadImageFormatException();
            BlobReader blob = pe.GetMetadata().GetReader(_metadata.GetHeapMetadataOffset(HeapIndex.UserString) + offset, size - offset);
            int length = blob.ReadCompressedInteger();
            if (length <= 0 || length > blob.RemainingBytes) throw new BadImageFormatException();
            return length <= 1025 ? blob.ReadUTF16(length - 1) : null;
        }
    }

    private struct Instruction(int code, int operand, string? literal)
    {
        internal int Code = code;
        internal int Operand = operand;
        internal string? Literal = literal;
        internal bool ProfilePath;
        internal bool Executable;
        internal readonly bool RemoteUrl => Literal?.StartsWith("https://", StringComparison.OrdinalIgnoreCase) == true ||
            Literal?.StartsWith("http://", StringComparison.OrdinalIgnoreCase) == true;
        internal readonly int? LoadLocal => Code switch { >= 0x06 and <= 0x09 => Code - 0x06, 0x11 or 0xfe0c => Operand, _ => null };
        internal readonly int? StoreLocal => Code switch { >= 0x0a and <= 0x0d => Code - 0x0a, 0x13 or 0xfe0e => Operand, _ => null };
    }

    private sealed class Facts
    {
        internal readonly HashSet<MethodDefinitionHandle> Calls = [];
        internal readonly HashSet<int> ProfilePaths = [], Executables = [], Downloaded = [];
        internal readonly HashSet<string> ResourceNames = new(StringComparer.Ordinal);
        internal bool LaunchesDownload, LoadsAssembly, InvokesMethod, RunKey, SetRegistryValue, CefFlag, Steam, Evaluate, ConnectSocket, SendSocket;
    }

    private static int ReadOperand(ref BlobReader il, OperandType type)
    {
        switch (type)
        {
            case OperandType.InlineNone: return 0;
            case OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar: return il.ReadByte();
            case OperandType.InlineVar: return il.ReadUInt16();
            case OperandType.InlineI8 or OperandType.InlineR: il.ReadInt64(); return 0;
            case OperandType.InlineSwitch:
                int count = il.ReadInt32();
                if (count < 0 || count > il.RemainingBytes / 4) throw new BadImageFormatException();
                il.Offset += count * 4; return 0;
            default: return il.ReadInt32();
        }
    }
}

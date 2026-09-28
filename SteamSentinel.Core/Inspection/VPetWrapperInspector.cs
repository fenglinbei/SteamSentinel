using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Inspection;

// Reads ECMA-335 metadata/IL only. No Assembly.Load, import resolution, or invocation of sample methods.
internal static class VPetWrapperInspector
{
    private static readonly Dictionary<ushort, OperandType> Operands = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!)
        .ToDictionary(op => unchecked((ushort)op.Value), op => op.OperandType);

    internal static VPetFamilyResult? Inspect(Stream input, string sourceHash, CancellationToken token, ContainerResourceBudget? budget = null)
    {
        if (input.Length is < 128 or > 2 * 1024 * 1024) return null;
        bool candidate = false;
        VPetFamilyEvidence evidence = new() { SourceSha256 = sourceHash, Role = VPetComponentRole.ManagedWrapper };
        try
        {
            input.Position = 0;
            using PEReader pe = new(input, PEStreamOptions.LeaveOpen | PEStreamOptions.PrefetchEntireImage);
            if (!pe.HasMetadata) return null;
            MetadataReader metadata = pe.GetMetadataReader();
            if (metadata.TypeDefinitions.Count > 512 || metadata.MethodDefinitions.Count > 4096 || metadata.MemberReferences.Count > 8192) return null;
            Dictionary<string, MethodDefinitionHandle> methods = new(StringComparer.Ordinal);
            foreach (TypeDefinitionHandle handle in metadata.TypeDefinitions)
            {
                token.ThrowIfCancellationRequested(); budget?.ChargeMetadata();
                TypeDefinition type = metadata.GetTypeDefinition(handle);
                string typeName = metadata.GetString(type.Name), ns = metadata.GetString(type.Namespace);
                if (ns != "SmartPet" || typeName is not ("PxBridge" or "PluginMain")) continue;
                candidate |= typeName == "PxBridge";
                if (typeName == "PluginMain" && Name(type.BaseType) != "VPet_Simulator.Windows.Interface.MainPlugin") return null;
                foreach (MethodDefinitionHandle method in type.GetMethods())
                    if (!methods.TryAdd(typeName + "::" + metadata.GetString(metadata.GetMethodDefinition(method).Name), method)) return null;
            }
            string[] required = ["PluginMain::LoadPlugin", "PluginMain::FindOrigDll", "PluginMain::EnsureInner",
                "PxBridge::RunNear", "PxBridge::FindSidecarDll", "PxBridge::GetProcAddressOrdinal", "PxBridge::LoadLibrary"];
            if (!candidate || required.Any(name => !methods.ContainsKey(name))) return null;
            MethodDefinition ordinal = metadata.GetMethodDefinition(methods["PxBridge::GetProcAddressOrdinal"]);
            if ((ordinal.Attributes & MethodAttributes.PinvokeImpl) == 0) return null;
            MethodImport import = ordinal.GetImport();
            if (metadata.GetString(import.Name) != "GetProcAddress" ||
                !metadata.GetString(metadata.GetModuleReference(import.Module).Name).Equals("kernel32.dll", StringComparison.OrdinalIgnoreCase)) return null;

            var load = Read(methods["PluginMain::LoadPlugin"]);
            var run = Read(methods["PxBridge::RunNear"]);
            var sidecar = Read(methods["PxBridge::FindSidecarDll"]);
            var orig = Read(methods["PluginMain::FindOrigDll"]);
            var inner = Read(methods["PluginMain::EnsureInner"]);
            bool callback = load.Functions.Any(handle => handle.Kind == HandleKind.MethodDefinition &&
                Read((MethodDefinitionHandle)handle).Calls.Contains("SmartPet.PxBridge::RunNear"));
            string[] loaderNames = sidecar.Strings.Where(LeafDll).Distinct().ToArray();
            string[] originalNames = orig.Strings.Where(value => LeafDll(value) && value.EndsWith(".orig.dll", StringComparison.Ordinal)).Distinct().ToArray();
            if (!load.Calls.Contains("System.Threading.ThreadPool::QueueUserWorkItem") || !callback ||
                !run.Calls.Contains("SmartPet.PxBridge::GetProcAddressOrdinal") || !run.Calls.Contains("SmartPet.PxBridge::LoadLibrary") ||
                !run.Calls.Contains("System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer") || !run.OrdinalOne ||
                !sidecar.Strings.Contains("native") || !orig.Strings.Contains("lib") ||
                !(inner.Calls.Contains("System.Reflection.Assembly::LoadFrom") || inner.Calls.Contains("System.Runtime.Loader.AssemblyLoadContext::LoadFromAssemblyPath")) ||
                loaderNames.Length != 1 || originalNames.Length != 1) return null;
            evidence.Status = VPetFamilyStatus.CodeMatched; evidence.ReasonCode = "VPET-WRAPPER-IL-LINK";
            evidence.Signals.AddRange(["VPET-WRAPPER-THREADED-SIDECAR", "VPET-ORDINAL-ONE", "VPET-ORIGINAL-DELEGATION"]);
            evidence.RelatedNames.AddRange([loaderNames[0], originalNames[0]]);
            return new(evidence);

            string Name(EntityHandle handle, int depth = 0)
            {
                if (depth > 8) throw new BadImageFormatException("Metadata reference depth.");
                return handle.Kind switch
                {
                    HandleKind.TypeReference => metadata.GetString(metadata.GetTypeReference((TypeReferenceHandle)handle).Namespace) + "." + metadata.GetString(metadata.GetTypeReference((TypeReferenceHandle)handle).Name),
                    HandleKind.TypeDefinition => metadata.GetString(metadata.GetTypeDefinition((TypeDefinitionHandle)handle).Namespace) + "." + metadata.GetString(metadata.GetTypeDefinition((TypeDefinitionHandle)handle).Name),
                    HandleKind.MemberReference => Name(metadata.GetMemberReference((MemberReferenceHandle)handle).Parent, depth + 1) + "::" + metadata.GetString(metadata.GetMemberReference((MemberReferenceHandle)handle).Name),
                    HandleKind.MethodDefinition => Name(metadata.GetMethodDefinition((MethodDefinitionHandle)handle).GetDeclaringType(), depth + 1) + "::" + metadata.GetString(metadata.GetMethodDefinition((MethodDefinitionHandle)handle).Name),
                    HandleKind.MethodSpecification => Name(metadata.GetMethodSpecification((MethodSpecificationHandle)handle).Method, depth + 1),
                    _ => string.Empty
                };
            }
            IlFacts Read(MethodDefinitionHandle handle)
            {
                token.ThrowIfCancellationRequested(); budget?.ChargeMetadata();
                MethodDefinition method = metadata.GetMethodDefinition(handle);
                if (method.RelativeVirtualAddress == 0) return new();
                byte[] il = pe.GetMethodBody(method.RelativeVirtualAddress).GetILBytes() ?? [];
                if (il.Length > 16384) throw new InvalidDataException("IL size limit.");
                IlFacts facts = new(); int p = 0;
                while (p < il.Length)
                {
                    token.ThrowIfCancellationRequested();
                    ushort op = il[p++];
                    if (op == 0xfe) { Need(1); op = (ushort)(0xfe00 | il[p++]); }
                    if (!Operands.TryGetValue(op, out OperandType operand)) throw new BadImageFormatException("IL opcode.");
                    int length = operand switch
                    {
                        OperandType.InlineNone => 0,
                        OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                        OperandType.InlineVar => 2,
                        OperandType.InlineI8 or OperandType.InlineR => 8,
                        _ => 4
                    };
                    Need(length);
                    if (operand == OperandType.InlineSwitch)
                    {
                        int count = BitConverter.ToInt32(il, p); p += 4;
                        if (count is < 0 or > 4096) throw new BadImageFormatException("IL switch limit.");
                        length = checked(count * 4); Need(length);
                    }
                    else if (op == 0x72)
                    {
                        int value = BitConverter.ToInt32(il, p);
                        if ((value & unchecked((int)0xff000000)) != 0x70000000) throw new BadImageFormatException("IL string token.");
                        string text = metadata.GetUserString(MetadataTokens.UserStringHandle(value & 0xffffff));
                        if (text.Length <= 256) facts.Strings.Add(text);
                    }
                    else if (op is 0x28 or 0x6f or 0xfe06 or 0xfe07)
                    {
                        EntityHandle target = MetadataTokens.EntityHandle(BitConverter.ToInt32(il, p));
                        if (op is 0xfe06 or 0xfe07) facts.Functions.Add(target); else facts.Calls.Add(Name(target));
                    }
                    else if (op == 0x17) facts.OrdinalOne = true;
                    p += length;
                }
                return facts;
                void Need(int count) { if (count > il.Length - p) throw new BadImageFormatException("Truncated IL."); }
            }
        }
        catch (Exception ex) when (ex is BadImageFormatException or InvalidDataException or ArgumentOutOfRangeException)
        {
            if (!candidate) return null;
            evidence.Status = VPetFamilyStatus.Malformed; evidence.ReasonCode = "VPET-WRAPPER-IL-INVALID";
            return new(evidence);
        }
    }

    private static bool LeafDll(string value) => value.Length is > 4 and <= 128 && !value.StartsWith('.') &&
        value.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-');
    private sealed class IlFacts
    {
        internal HashSet<string> Calls { get; } = new(StringComparer.Ordinal);
        internal HashSet<string> Strings { get; } = new(StringComparer.Ordinal);
        internal List<EntityHandle> Functions { get; } = [];
        internal bool OrdinalOne { get; set; }
    }
}

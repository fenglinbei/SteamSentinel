using System.Collections.Immutable;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;

namespace SteamSentinel.Core.Inspection;

public sealed record SteamAlertEmbeddedProof(string RuleId, string ResourceName, string PayloadSha256, int EntryPointToken);

/// <summary>
/// Bounded, static proof of the supported resident bootstrap. Tracks the actual resource bytes through
/// CopyTo/ToArray/Assembly.Load and reflection, rather than treating API/string cooccurrence as proof.
/// Unsupported transformations, escaped values and exhausted analysis budgets fail closed.
/// </summary>
public static class SteamAlertEmbeddedEvidence
{
    public const string RuleId = "STEAMALERT-EMBEDDED-CORE-HOST";
    public const string ReasonCode = "EmbeddedKnownCoreBoundToEntryPoint";
    public const long MaximumBytes = 8L * 1024 * 1024;
    private const int MaximumResourceBytes = 4 * 1024 * 1024;
    private static readonly Dictionary<short, OpCode> Opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!).ToDictionary(op => op.Value);

    public static SteamAlertEmbeddedProof? Inspect(Stream stream, RuleSet? rules = null, CancellationToken token = default)
    {
        if (!stream.CanSeek || !stream.CanRead) return null;
        long position = stream.Position;
        try
        {
            token.ThrowIfCancellationRequested();
            if (stream.Length is < 128 or > MaximumBytes) return null;
            stream.Position = 0;
            using PEReader pe = new(stream, PEStreamOptions.LeaveOpen);
            if (!pe.HasMetadata || pe.PEHeaders.CorHeader is not { MetadataDirectory.Size: > 0 and <= 2 * 1024 * 1024 } cor ||
                cor.Flags.HasFlag(CorFlags.NativeEntryPoint) || pe.PEHeaders.CoffHeader.Characteristics.HasFlag(Characteristics.Dll)) return null;
            MetadataReader metadata = pe.GetMetadataReader(MetadataReaderOptions.None);
            if (metadata.ManifestResources.Count is 0 or > 128 || metadata.MethodDefinitions.Count > 8192) return null;
            EntityHandle entry = MetadataTokens.EntityHandle(cor.EntryPointTokenOrRelativeVirtualAddress);
            if (entry.Kind != HandleKind.MethodDefinition) return null;
            MethodDefinition method = metadata.GetMethodDefinition((MethodDefinitionHandle)entry);
            if (!method.Attributes.HasFlag(MethodAttributes.Static) || method.RelativeVirtualAddress == 0 ||
                (method.ImplAttributes & MethodImplAttributes.CodeTypeMask) != MethodImplAttributes.IL) return null;
            MethodBodyBlock body = pe.GetMethodBody(method.RelativeVirtualAddress);
            if (body.GetILReader().Length > 64 * 1024 || body.ExceptionRegions.Length > 32) return null;
            return new Analysis(pe, metadata, body, rules ?? RuleLoader.LoadEmbedded(), token).Run(cor.EntryPointTokenOrRelativeVirtualAddress);
        }
        catch (Exception error) when (error is BadImageFormatException or ArgumentException or InvalidOperationException or OverflowException or IndexOutOfRangeException)
        { return null; }
        finally { stream.Position = position; }
    }

    private enum ValueKind { Unknown, Null, Integer, Text, HostTypeHandle, HostType, OwnAssembly, Resource, Memory, Bytes, LoadedAssembly, CoreType, RunMethod, Arguments }
    private readonly record struct Value(ValueKind Kind = ValueKind.Unknown, string? Text = null, int Number = 0)
    {
        internal bool Tracked => (int)Kind >= (int)ValueKind.HostTypeHandle;
        internal bool? Truth => Kind switch { ValueKind.Unknown => null, ValueKind.Null => false, ValueKind.Integer => Number != 0, _ => true };
    }
    private sealed class State
    {
        internal int Offset, NextId;
        internal readonly List<Value> Stack = [];
        internal readonly Dictionary<int, Value> Locals = [];
        internal readonly Dictionary<int, string?> Memories = [];
        internal readonly Dictionary<int, Value[]> Arrays = [];
        internal readonly HashSet<int> DisposedResources = [];
        internal readonly HashSet<int> ConsumedResources = [];
        internal readonly List<int> FinallyReturns = [];
        internal bool HasTracked => Stack.Any(v => v.Tracked) || Locals.Values.Any(v => v.Tracked);
        internal State Clone()
        {
            State result = new() { Offset = Offset, NextId = NextId };
            result.Stack.AddRange(Stack);
            foreach (var pair in Locals) result.Locals.Add(pair.Key, pair.Value);
            foreach (var pair in Memories) result.Memories.Add(pair.Key, pair.Value);
            foreach (var pair in Arrays) result.Arrays.Add(pair.Key, (Value[])pair.Value.Clone());
            result.DisposedResources.UnionWith(DisposedResources);
            result.ConsumedResources.UnionWith(ConsumedResources);
            result.FinallyReturns.AddRange(FinallyReturns);
            return result;
        }
        internal Value Pop()
        {
            if (Stack.Count == 0) throw new BadImageFormatException();
            Value value = Stack[^1]; Stack.RemoveAt(Stack.Count - 1); return value;
        }
    }
    private readonly record struct Instruction(int Offset, int Next, OpCode Op, int Operand);

    private sealed class Analysis(PEReader pe, MetadataReader metadata, MethodBodyBlock body, RuleSet rules, CancellationToken token)
    {
        private readonly Dictionary<int, Instruction> _instructions = [];
        private readonly Dictionary<string, string?> _resources = new(StringComparer.Ordinal);
        private int _resourceBytes;
        private readonly Types _types = new(metadata);

        internal SteamAlertEmbeddedProof? Run(int entryToken)
        {
            Decode();
            Queue<State> pending = new(); pending.Enqueue(new());
            int steps = 0, forks = 0;
            while (pending.TryDequeue(out State? state))
            {
                while (_instructions.TryGetValue(state.Offset, out Instruction instruction))
                {
                    if (++steps > 16384 || state.Stack.Count > 64 || state.Locals.Count > 128 || state.NextId > 128) return null;
                    if ((steps & 127) == 0) token.ThrowIfCancellationRequested();
                    short code = instruction.Op.Value;
                    state.Offset = instruction.Next;
                    if (code == OpCodes.Nop.Value) continue;
                    if (code == OpCodes.Ret.Value || code == OpCodes.Throw.Value || code == OpCodes.Rethrow.Value) break;
                    if (code == OpCodes.Ldnull.Value) { state.Stack.Add(new(ValueKind.Null)); continue; }
                    if (code == OpCodes.Ldstr.Value) { state.Stack.Add(new(ValueKind.Text, UserString(instruction.Operand))); continue; }
                    if (code is >= 0x15 and <= 0x1e) { state.Stack.Add(new(ValueKind.Integer, Number: code - 0x16)); continue; }
                    if (code == OpCodes.Ldc_I4.Value || code == OpCodes.Ldc_I4_S.Value)
                    { state.Stack.Add(new(ValueKind.Integer, Number: instruction.Operand)); continue; }
                    int? local = code switch { >= 0x06 and <= 0x09 => code - 0x06, 0x11 or unchecked((short)0xfe0c) => instruction.Operand, _ => null };
                    if (local is int load) { state.Stack.Add(state.Locals.GetValueOrDefault(load)); continue; }
                    local = code switch { >= 0x0a and <= 0x0d => code - 0x0a, 0x13 or unchecked((short)0xfe0e) => instruction.Operand, _ => null };
                    if (local is int store) { state.Locals[store] = state.Pop(); continue; }
                    if (code == OpCodes.Dup.Value) { Value value = state.Pop(); state.Stack.Add(value); state.Stack.Add(value); continue; }
                    if (code == OpCodes.Pop.Value) { state.Pop(); continue; }
                    if (code == OpCodes.Ldtoken.Value)
                    {
                        EntityHandle handle = MetadataTokens.EntityHandle(instruction.Operand);
                        state.Stack.Add(handle.Kind == HandleKind.TypeDefinition ? new(ValueKind.HostTypeHandle) : default);
                        continue;
                    }
                    if (code == OpCodes.Br.Value || code == OpCodes.Br_S.Value)
                    { if (!Branch(state, instruction, instruction.Next + instruction.Operand)) break; continue; }
                    if (code == OpCodes.Brtrue.Value || code == OpCodes.Brtrue_S.Value || code == OpCodes.Brfalse.Value || code == OpCodes.Brfalse_S.Value)
                    {
                        bool whenTrue = code == OpCodes.Brtrue.Value || code == OpCodes.Brtrue_S.Value;
                        bool? truth = state.Pop().Truth;
                        if (truth is null)
                        {
                            if (++forks > 256) return null;
                            State taken = state.Clone();
                            if (Branch(taken, instruction, instruction.Next + instruction.Operand)) pending.Enqueue(taken);
                        }
                        else if (truth == whenTrue && !Branch(state, instruction, instruction.Next + instruction.Operand)) break;
                        continue;
                    }
                    if (code == OpCodes.Leave.Value || code == OpCodes.Leave_S.Value)
                    {
                        int target = instruction.Next + instruction.Operand;
                        if (!_instructions.ContainsKey(target) || state.FinallyReturns.Count != 0) break;
                        var handlers = body.ExceptionRegions.Where(r => r.Kind == ExceptionRegionKind.Finally &&
                            In(instruction.Offset, r.TryOffset, r.TryLength) && !In(target, r.TryOffset, r.TryLength)).OrderBy(r => r.TryLength).ToArray();
                        state.Stack.Clear();
                        if (handlers.Length == 0) state.Offset = target;
                        else
                        {
                            state.FinallyReturns.Add(target);
                            for (int index = handlers.Length - 1; index > 0; index--) state.FinallyReturns.Add(handlers[index].HandlerOffset);
                            state.Offset = handlers[0].HandlerOffset;
                        }
                        continue;
                    }
                    if (code == OpCodes.Endfinally.Value)
                    {
                        if (state.FinallyReturns.Count == 0) break;
                        state.Stack.Clear(); state.Offset = state.FinallyReturns[^1]; state.FinallyReturns.RemoveAt(state.FinallyReturns.Count - 1); continue;
                    }
                    if (code == OpCodes.Newarr.Value)
                    {
                        Value length = state.Pop();
                        if (_types.Name(MetadataTokens.EntityHandle(instruction.Operand)) != "System.Object" || length is not { Kind: ValueKind.Integer, Number: 1 }) break;
                        int id = ++state.NextId; state.Arrays.Add(id, [new(ValueKind.Null)]); state.Stack.Add(new(ValueKind.Arguments, Number: id)); continue;
                    }
                    if (code == OpCodes.Stelem_Ref.Value)
                    {
                        Value value = state.Pop(), index = state.Pop(), array = state.Pop();
                        if (array.Kind != ValueKind.Arguments || index is not { Kind: ValueKind.Integer, Number: 0 } || value.Kind is not (ValueKind.Text or ValueKind.Null)) break;
                        state.Arrays[array.Number][0] = value; continue;
                    }
                    if (code == OpCodes.Call.Value || code == OpCodes.Callvirt.Value || code == OpCodes.Newobj.Value)
                    {
                        if (!Call(state, instruction, out string? invoked)) break;
                        if (invoked is not null) return new(RuleId, invoked, _resources[invoked]!, entryToken);
                        continue;
                    }
                    // Unknown mutations cannot preserve a payload proof. Before a proof begins, ordinary
                    // fixed-stack bootstrap instructions are harmless; no unknown value gains provenance.
                    if (state.HasTracked || instruction.Op.FlowControl is FlowControl.Branch or FlowControl.Cond_Branch ||
                        !FixedStack(state, instruction.Op)) break;
                }
            }
            return null;
        }

        private bool Call(State state, Instruction instruction, out string? invoked)
        {
            invoked = null;
            EntityHandle handle = MetadataTokens.EntityHandle(instruction.Operand);
            if (handle.Kind == HandleKind.MethodSpecification) return false;
            MethodSignature<string> signature;
            string owner = "", name = "";
            if (handle.Kind == HandleKind.MemberReference)
            {
                MemberReference member = metadata.GetMemberReference((MemberReferenceHandle)handle);
                signature = member.DecodeMethodSignature(_types, (object?)null);
                owner = _types.Name(member.Parent); name = metadata.GetString(member.Name);
            }
            else if (handle.Kind == HandleKind.MethodDefinition)
                signature = metadata.GetMethodDefinition((MethodDefinitionHandle)handle).DecodeSignature(_types, (object?)null);
            else return false;
            if (signature.ParameterTypes.Length > 32 || signature.Header.IsGeneric || signature.Header.CallingConvention == SignatureCallingConvention.VarArgs) return false;
            Value[] args = new Value[signature.ParameterTypes.Length];
            for (int index = args.Length - 1; index >= 0; index--) args[index] = state.Pop();
            bool constructor = instruction.Op.Value == OpCodes.Newobj.Value;
            Value receiver = signature.Header.IsInstance && !constructor ? state.Pop() : default;
            bool Api(string type, string method, bool instance, string result, params string[] parameters) => owner == type && name == method &&
                signature.Header.IsInstance == instance && signature.ReturnType == result && signature.ParameterTypes.SequenceEqual(parameters);
            Value value = default;
            bool recognized = true;
            if (Api("System.Reflection.Assembly", "GetExecutingAssembly", false, "System.Reflection.Assembly")) value = new(ValueKind.OwnAssembly);
            else if (Api("System.Type", "GetTypeFromHandle", false, "System.Type", "System.RuntimeTypeHandle") && args[0].Kind == ValueKind.HostTypeHandle) value = new(ValueKind.HostType);
            else if (Api("System.Type", "get_Assembly", true, "System.Reflection.Assembly") && receiver.Kind == ValueKind.HostType) value = new(ValueKind.OwnAssembly);
            else if (Api("System.Reflection.Assembly", "GetManifestResourceStream", true, "System.IO.Stream", "System.String") &&
                receiver.Kind == ValueKind.OwnAssembly && args[0] is { Kind: ValueKind.Text, Text: { } resource } && Resource(resource) is not null)
            { value = new(ValueKind.Resource, resource, ++state.NextId); }
            else if (constructor && Api("System.IO.MemoryStream", ".ctor", true, "System.Void"))
            { int id = ++state.NextId; state.Memories.Add(id, null); value = new(ValueKind.Memory, Number: id); }
            else if (Api("System.IO.Stream", "CopyTo", true, "System.Void", "System.IO.Stream") && receiver is { Kind: ValueKind.Resource, Text: { } copied } &&
                args[0].Kind == ValueKind.Memory && !state.DisposedResources.Contains(receiver.Number) &&
                !state.ConsumedResources.Contains(receiver.Number) && state.Memories[args[0].Number] is null)
            { state.Memories[args[0].Number] = copied; state.ConsumedResources.Add(receiver.Number); }
            else if (Api("System.IO.MemoryStream", "ToArray", true, "System.Byte[]") && receiver.Kind == ValueKind.Memory && state.Memories[receiver.Number] is { } bytes)
                value = new(ValueKind.Bytes, bytes);
            else if (Api("System.Reflection.Assembly", "Load", false, "System.Reflection.Assembly", "System.Byte[]") && args[0].Kind == ValueKind.Bytes)
                value = new(ValueKind.LoadedAssembly, args[0].Text);
            else if (Api("System.Reflection.Assembly", "GetType", true, "System.Type", "System.String") && receiver.Kind == ValueKind.LoadedAssembly &&
                args[0] is { Kind: ValueKind.Text, Text: "SteamAlertCore.Core" }) value = new(ValueKind.CoreType, receiver.Text);
            else if (Api("System.Type", "GetMethod", true, "System.Reflection.MethodInfo", "System.String") && receiver.Kind == ValueKind.CoreType &&
                args[0] is { Kind: ValueKind.Text, Text: "Run" }) value = new(ValueKind.RunMethod, receiver.Text);
            else if ((Api("System.Reflection.MethodBase", "Invoke", true, "System.Object", "System.Object", "System.Object[]") ||
                Api("System.Reflection.MethodInfo", "Invoke", true, "System.Object", "System.Object", "System.Object[]")) && receiver.Kind == ValueKind.RunMethod &&
                args[0].Kind == ValueKind.Null && args[1].Kind == ValueKind.Arguments && state.Arrays[args[1].Number][0].Kind is ValueKind.Text or ValueKind.Null)
                invoked = receiver.Text;
            else if (Api("System.Type", "op_Equality", false, "System.Boolean", "System.Type", "System.Type"))
                value = args[0].Kind == ValueKind.CoreType && args[1].Kind == ValueKind.Null || args[1].Kind == ValueKind.CoreType && args[0].Kind == ValueKind.Null
                    ? new(ValueKind.Integer, Number: 0) : default;
            else if (Api("System.IDisposable", "Dispose", true, "System.Void") || Api("System.IO.Stream", "Dispose", true, "System.Void") ||
                Api("System.IO.MemoryStream", "Dispose", true, "System.Void"))
            {
                if (receiver.Kind == ValueKind.Resource) state.DisposedResources.Add(receiver.Number);
                else if (receiver.Kind != ValueKind.Memory) recognized = false;
            }
            else recognized = false;
            if (!recognized && (state.HasTracked || receiver.Tracked || args.Any(v => v.Tracked))) return false;
            if (constructor || signature.ReturnType != "System.Void") state.Stack.Add(value);
            return true;
        }

        private string? Resource(string name)
        {
            if (_resources.TryGetValue(name, out string? cached)) return cached;
            _resources.Add(name, null);
            if (_resources.Count > 8) return null;
            ManifestResource[] matches = metadata.ManifestResources.Select(metadata.GetManifestResource)
                .Where(resource => resource.Implementation.IsNil && metadata.StringComparer.Equals(resource.Name, name)).Take(2).ToArray();
            if (matches.Length != 1) return null;
            DirectoryEntry directory = pe.PEHeaders.CorHeader!.ResourcesDirectory;
            if (directory.Size < 4 || directory.Size > MaximumBytes || matches[0].Offset < 0) return null;
            PEMemoryBlock block = pe.GetSectionData(directory.RelativeVirtualAddress);
            long offset = matches[0].Offset;
            int available = Math.Min(directory.Size, block.Length);
            if (offset > available - 4) return null;
            int length = block.GetReader((int)offset, 4).ReadInt32();
            if (length < 128 || length > MaximumResourceBytes - _resourceBytes || length > available - offset - 4) return null;
            _resourceBytes += length;
            ImmutableArray<byte> data = block.GetContent((int)offset + 4, length);
            string hash = Convert.ToHexString(SHA256.HashData(data.AsSpan()));
            if (!rules.KnownHashes.Any(rule => rule.Id is "STEAMALERT-CORE" or "STEAMALERT-CORE-20261117" && rule.Malware &&
                rule.Sha256.Equals(hash, StringComparison.OrdinalIgnoreCase))) return null;
            using PEReader core = new(data);
            if (!core.HasMetadata || core.PEHeaders.CorHeader is not { MetadataDirectory.Size: > 0 and <= 2 * 1024 * 1024 }) return null;
            MetadataReader payload = core.GetMetadataReader(MetadataReaderOptions.None);
            if (payload.TypeDefinitions.Count > 4096 || payload.MethodDefinitions.Count > 8192) return null;
            Types types = new(payload);
            int methods = 0;
            foreach (TypeDefinitionHandle typeHandle in payload.TypeDefinitions)
            {
                TypeDefinition type = payload.GetTypeDefinition(typeHandle);
                if (!payload.StringComparer.Equals(type.Namespace, "SteamAlertCore") || !payload.StringComparer.Equals(type.Name, "Core")) continue;
                foreach (MethodDefinitionHandle methodHandle in type.GetMethods())
                {
                    MethodDefinition method = payload.GetMethodDefinition(methodHandle);
                    if (!payload.StringComparer.Equals(method.Name, "Run") || !method.Attributes.HasFlag(MethodAttributes.Public)) continue;
                    MethodSignature<string> signature = method.DecodeSignature(types, (object?)null);
                    // GetMethod(string) must resolve one unambiguous public static Run(string).
                    if (!method.Attributes.HasFlag(MethodAttributes.Static) || signature.Header.IsGeneric || signature.Header.IsInstance ||
                        signature.ReturnType != "System.Void" || !signature.ParameterTypes.SequenceEqual(["System.String"]) || method.RelativeVirtualAddress == 0) return null;
                    methods++;
                }
            }
            if (methods != 1) return null;
            return _resources[name] = hash;
        }

        private void Decode()
        {
            BlobReader reader = body.GetILReader();
            while (reader.RemainingBytes > 0)
            {
                int offset = reader.Offset, code = reader.ReadByte();
                if (code == 0xfe) code = 0xfe00 | reader.ReadByte();
                if (!Opcodes.TryGetValue(unchecked((short)code), out OpCode op)) throw new BadImageFormatException();
                int operand = op.OperandType switch
                {
                    OperandType.InlineNone => 0,
                    OperandType.ShortInlineBrTarget or OperandType.ShortInlineI => reader.ReadSByte(),
                    OperandType.ShortInlineVar => reader.ReadByte(),
                    OperandType.InlineVar => reader.ReadUInt16(),
                    OperandType.InlineI8 or OperandType.InlineR => Skip64(ref reader),
                    OperandType.InlineSwitch => throw new BadImageFormatException(),
                    _ => reader.ReadInt32()
                };
                _instructions.Add(offset, new(offset, reader.Offset, op, operand));
            }
        }
        private static int Skip64(ref BlobReader reader) { reader.ReadInt64(); return 0; }
        private bool Branch(State state, Instruction instruction, int target)
        {
            if (!_instructions.ContainsKey(target)) return false;
            foreach (ExceptionRegion region in body.ExceptionRegions)
                if (In(instruction.Offset, region.TryOffset, region.TryLength) != In(target, region.TryOffset, region.TryLength) ||
                    In(instruction.Offset, region.HandlerOffset, region.HandlerLength) != In(target, region.HandlerOffset, region.HandlerLength)) return false;
            state.Offset = target; return true;
        }
        private static bool In(int offset, int start, int length) => offset >= start && offset < start + length;
        private string? UserString(int operand)
        {
            if ((uint)operand >> 24 != 0x70) throw new BadImageFormatException();
            int offset = operand & 0xffffff, size = metadata.GetHeapSize(HeapIndex.UserString);
            if (offset >= size) throw new BadImageFormatException();
            BlobReader blob = pe.GetMetadata().GetReader(metadata.GetHeapMetadataOffset(HeapIndex.UserString) + offset, size - offset);
            int length = blob.ReadCompressedInteger();
            if (length <= 0 || length > blob.RemainingBytes) throw new BadImageFormatException();
            return length <= 1025 ? blob.ReadUTF16(length - 1) : null;
        }
        private static bool FixedStack(State state, OpCode op)
        {
            int pop = op.StackBehaviourPop switch
            {
                StackBehaviour.Pop0 => 0,
                StackBehaviour.Pop1 or StackBehaviour.Popi or StackBehaviour.Popref => 1,
                StackBehaviour.Pop1_pop1 or StackBehaviour.Popi_pop1 or StackBehaviour.Popi_popi or StackBehaviour.Popi_popi8 or
                    StackBehaviour.Popi_popr4 or StackBehaviour.Popi_popr8 or StackBehaviour.Popref_pop1 or StackBehaviour.Popref_popi => 2,
                _ => -1
            };
            int push = op.StackBehaviourPush switch
            {
                StackBehaviour.Push0 => 0,
                StackBehaviour.Push1 or StackBehaviour.Pushi or StackBehaviour.Pushi8 or StackBehaviour.Pushr4 or StackBehaviour.Pushr8 or StackBehaviour.Pushref => 1,
                _ => -1
            };
            if (pop < 0 || push < 0) return false;
            while (pop-- > 0) state.Pop();
            while (push-- > 0) state.Stack.Add(default);
            return true;
        }
    }

    // Framework spelling alone is insufficient: local fake Assembly/Stream classes must never grant proof.
    private sealed class Types(MetadataReader metadata) : ISignatureTypeProvider<string, object?>
    {
        internal string Name(EntityHandle handle)
        {
            if (handle.Kind != HandleKind.TypeReference) return "?";
            TypeReference type = metadata.GetTypeReference((TypeReferenceHandle)handle);
            if (type.ResolutionScope.Kind != HandleKind.AssemblyReference) return "?";
            AssemblyReference assembly = metadata.GetAssemblyReference((AssemblyReferenceHandle)type.ResolutionScope);
            string assemblyName = metadata.GetString(assembly.Name);
            byte[] key = metadata.GetBlobBytes(assembly.PublicKeyOrToken);
            if (assembly.Flags.HasFlag(AssemblyFlags.PublicKey))
            {
                if (key.Length is < 64 or > 1024) return "?";
                // Metadata may carry the full strong-name public key instead of its eight-byte token.
                byte[] digest = SHA1.HashData(key);
                key = digest[^8..]; Array.Reverse(key);
            }
            if (key.Length != 8) return "?";
            string token = Convert.ToHexString(key);
            bool trusted = assemblyName == "mscorlib" && token == "B77A5C561934E089" ||
                assemblyName == "System.Private.CoreLib" && token == "7CEC85D7BEA7798E" ||
                assemblyName is "System.Runtime" or "System.Reflection" or "System.Reflection.Primitives" or "System.IO" && token == "B03F5F7F11D50A3A";
            return trusted ? metadata.GetString(type.Namespace) + "." + metadata.GetString(type.Name) : "?";
        }
        public string GetArrayType(string elementType, ArrayShape shape) => "?";
        public string GetByReferenceType(string elementType) => elementType + "&";
        public string GetFunctionPointerType(MethodSignature<string> signature) => "?";
        public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) => "?";
        public string GetGenericMethodParameter(object? genericContext, int index) => "?";
        public string GetGenericTypeParameter(object? genericContext, int index) => "?";
        public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => "?";
        public string GetPinnedType(string elementType) => "?";
        public string GetPointerType(string elementType) => "?";
        public string GetPrimitiveType(PrimitiveTypeCode typeCode) => "System." + typeCode;
        public string GetSZArrayType(string elementType) => elementType + "[]";
        public string GetTypeFromDefinition(MetadataReader reader, TypeDefinitionHandle handle, byte rawTypeKind) => "?";
        public string GetTypeFromReference(MetadataReader reader, TypeReferenceHandle handle, byte rawTypeKind) => Name(handle);
        public string GetTypeFromSpecification(MetadataReader reader, object? genericContext, TypeSpecificationHandle handle, byte rawTypeKind) => "?";
    }
}

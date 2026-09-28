using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030Step4Async(string root)
    {
        await TestV030FamilyBoundsAsync(root);
        TestV030ComponentLinks();
        await TestV030SteamUiAsync(root);
    }

    private static async Task<int> RunV030Step4Async(string root)
    {
        Directory.CreateDirectory(root);
        try { await TestV030Step4Async(root); }
        catch (Exception exception) { Failures.Add(exception.ToString()); Console.Error.WriteLine(exception); }
        await JsonFile.WriteAtomicAsync(Path.Combine(root, "results.json"), new
        { passed = _passed, failed = Failures.Count, skipped = _skipped, failures = Failures, version = ProductInfo.Version, buildIdentity = ProductInfo.BuildIdentity });
        Console.WriteLine($"V030_STEP4_PASS={_passed};FAIL={Failures.Count};SKIP={_skipped}");
        return Failures.Count == 0 ? 0 : 1;
    }

    private static async Task TestV030FamilyBoundsAsync(string root)
    {
        string directory = Path.Combine(root, "v030-family"); Directory.CreateDirectory(directory);
        foreach (bool credential in new[] { false, true })
        {
            var (encoded, plain) = V030InertEnvelope(credential);
            string sourceHash = Hashing.Sha256Bytes(encoded), derivedHash = Hashing.Sha256Bytes(plain);
            using MemoryStream input = new(encoded, false);
            ContainerResourceBudget budget = new(new());
            VPetFamilyResult? result = await VPetFamilyDecoder.InspectAsync(input, sourceHash, default, budget);
            Check("0.3 第4步 受限数据区重建与原始内容逐字节一致", result?.Decoded?.SequenceEqual(plain) == true && result.Evidence.Status == VPetFamilyStatus.Decoded);
            Check("0.3 第4步 原件与派生身份分开且变换不改源缓冲", result?.Evidence.SourceSha256 == sourceHash && result.Evidence.DerivedSha256 == derivedHash &&
                sourceHash != derivedHash && Hashing.Sha256Bytes(encoded) == sourceHash && result.Evidence.EnvelopeValidated);
            Check("0.3 第4步 两段解码范围及角色保留", result?.Evidence.Regions.Count == 2 && result.Evidence.Regions[0].Offset == 1024 &&
                result.Evidence.Regions[1].Offset == 2048 && result.Evidence.Role == (credential ? VPetComponentRole.CredentialPayload : VPetComponentRole.UiPayload));
            Check("0.3 第4步 派生计量纳入共享解码及展开预算", budget.Snapshot().DecodedBytes == plain.Length && budget.AcceptedExpandedBytes == plain.Length);
            byte[]? buffer = result?.Decoded; result?.Dispose();
            Check("0.3 第4步 派生字节使用后清除", buffer is not null && buffer.All(b => b == 0));

            string path = Path.Combine(directory, credential ? "credential-inert.dat" : "ui-inert.dat");
            await File.WriteAllBytesAsync(path, encoded);
            ScanReport report = await new ScanCoordinator(RuleLoader.LoadEmbedded()).RunAsync(V030ContentOptions(path));
            Finding? finding = report.Findings.SingleOrDefault(f => f.RuleId == "VPET-FAMILY-STRUCTURE");
            Check("0.3 第4步 未知整件哈希的有界解码语义仅供复核", finding is { IsKnownMalware: false, CanRemediate: false } &&
                finding.Sha256 == sourceHash && finding.TargetSha256 == sourceHash && finding.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
            Check("0.3 第4步 已验证家族尾部取消未知范围缺口", report.Containers?.Nodes.Any(n => n.Format == "VPet 家族尾部配置" && n.Overall == ContainerStageStatus.Complete) == true &&
                !report.Containers.Nodes.Any(n => n.Kind == ContainerNodeKind.UnknownRange));
            ReportBatchReader reader = new();
            ReportBatchWriter writer = new(batch => reader.Apply(JsonSerializer.Deserialize<ReportBatch>(JsonSerializer.Serialize(batch, JsonFile.Options), JsonFile.Options)!));
            writer.Send(report, true);
            Check("0.3 第4步 Worker 分片保留原件及派生证据", reader.Report?.Containers?.Nodes.Single(n => n.VPetFamily is not null).VPetFamily?.DerivedSha256 == derivedHash);
            string exported = Path.Combine(directory, credential ? "credential-report.json" : "ui-report.json");
            await ReportExporter.ExportJsonAsync(report, exported);
            string json = await File.ReadAllTextAsync(exported);
            Check("0.3 第4步 普通 JSON 导出只含元数据不含重建字节", json.Contains(derivedHash, StringComparison.Ordinal) &&
                !json.Contains(Convert.ToBase64String(plain), StringComparison.Ordinal));
            ContainerScanNode original = report.Containers!.Nodes.Single(n => n.VPetFamily is not null);
            foreach (Action<ContainerScanNode> corrupt in new Action<ContainerScanNode>[]
            {
                n => n.Sha256 = new string('B', 64),
                n => n.VPetFamily!.DerivedLength++,
                n => n.VPetFamily!.FooterLength = 1,
                n => n.VPetFamily!.Regions[1] = n.VPetFamily.Regions[0],
                n => n.VPetFamily!.Regions[1] = new(12288, 2560, 1),
                n => n.VPetFamily!.Status = VPetFamilyStatus.Malformed,
                n => n.VPetFamily!.RelatedNodeIds.Add(n.NodeId),
                n => n.VPetFamily!.Signals.Add(new string('x', 129))
            })
            {
                ContainerScanNode copy = JsonSerializer.Deserialize<ContainerScanNode>(JsonSerializer.Serialize(original, JsonFile.Options), JsonFile.Options)!;
                corrupt(copy); bool rejected = false;
                try { ContainerScanFragments.ValidateNode(copy); } catch (InvalidDataException) { rejected = true; }
                Check("0.3 第4步 协议拒绝错误源身份、派生范围或关联字段", rejected);
            }
            Check("0.3 第4步 UI 与 Markdown 展示解码身份和范围", ContainerReportPresentation.Describe(report.Containers).Contains(derivedHash, StringComparison.Ordinal));
        }

        byte[] good = V030InertEnvelope(false).Encoded;
        List<(string Name, byte[] Data)> malformed = [];
        void Bad(string name, Action<byte[]> change) { byte[] bytes = good.ToArray(); change(bytes); malformed.Add((name, bytes)); }
        Bad("DOS signature", b => b[0] = 0);
        Bad("PE offset overflow", b => V030U32(b, 60, uint.MaxValue));
        Bad("too many sections", b => BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(0x86), 97));
        Bad("optional directories", b => V030U32(b, 0x98 + 108, 17));
        Bad("raw overlap", b => V030U32(b, 0x188 + 40 + 20, 512));
        Bad("RVA overlap", b => V030U32(b, 0x188 + 40 + 12, 4096));
        Bad("duplicate section", b => Array.Copy(b, 0x188, b, 0x188 + 40, 8));
        Bad("section outside file", b => V030U32(b, 0x188 + 80 + 20, uint.MaxValue));
        Bad("range into code", b => V030U32(b, 2560 + 88, 4096));
        Bad("range into headers", b => V030U32(b, 2560 + 88, 128));
        Bad("oversized range", b => V030U32(b, 2560 + 92, uint.MaxValue));
        Bad("duplicate decode range", b => Array.Copy(b, 2560 + 88, b, 2560 + 96, 8));
        Bad("executable data section", b => V030U32(b, 0x188 + 80 + 36, 0xe0000040));
        Bad("export count", b => b[1024 + 20] ^= 2);
        Bad("forwarded export", b => { b[1072] ^= 0; b[1073] ^= 0x30; });
        Bad("encrypted key corruption", b => b[2560 + 8] ^= 1);
        malformed.Add(("truncated body", good[..^20].Concat(BitConverter.GetBytes(104u)).ToArray()));
        malformed.Add(("extra byte", good[..^4].Concat(new byte[] { 1 }).Concat(BitConverter.GetBytes(104u)).ToArray()));
        foreach (var item in malformed)
        {
            using MemoryStream input = new(item.Data, false);
            using var result = await VPetFamilyDecoder.InspectAsync(input, Hashing.Sha256Bytes(item.Data), default);
            Check("0.3 第4步 非法封装拒绝且不发布解码内容：" + item.Name, result is { Decoded: null } &&
                result.Evidence.Status is VPetFamilyStatus.Malformed or VPetFamilyStatus.Unsupported && !result.Evidence.EnvelopeValidated);
        }
        byte[] wrongModule = good.ToArray(); wrongModule[1088] ^= 1;
        using (MemoryStream input = new(wrongModule, false))
        using (var result = await VPetFamilyDecoder.InspectAsync(input, Hashing.Sha256Bytes(wrongModule), default))
            Check("0.3 第4步 解码导出身份不支持时不接受封装", result?.Evidence.Status == VPetFamilyStatus.Unsupported && result.Decoded is null);
        using (MemoryStream input = new(good, false))
        using (var result = await VPetFamilyDecoder.InspectAsync(input, Hashing.Sha256Bytes(good), default, maximumBytes: good.Length - 1))
            Check("0.3 第4步 单文件上限先于解码", result?.Evidence.Status == VPetFamilyStatus.LimitReached && result.Decoded is null);
        using (MemoryStream input = new(good, false))
        using (var result = await VPetFamilyDecoder.InspectAsync(input, Hashing.Sha256Bytes(good), default, new(new() { MaximumExpandedBytes = 2559 })))
            Check("0.3 第4步 派生展开预算不足明确保留缺口", result?.Evidence.ReasonCode == "VPET-DECODE-BUDGET" && result.Decoded is null);
        using (MemoryStream input = new(good, false))
        using (var result = await VPetFamilyDecoder.InspectAsync(input, Hashing.Sha256Bytes(good), default, new(new() { MaximumWorkBytes = 5119 })))
            Check("0.3 第4步 累计工作预算不足不解码", result?.Evidence.ReasonCode == "VPET-DECODE-BUDGET" && result.Decoded is null);
        byte[] large = new byte[VPetFamilyDecoder.MaximumInputBytes + 1]; good.CopyTo(large, 0); V030U32(large, large.Length - 4, 104);
        using (MemoryStream input = new(large, false))
        using (var result = await VPetFamilyDecoder.InspectAsync(input, Hashing.Sha256Bytes(large), default))
            Check("0.3 第4步 固定 8 MiB 输入限制", result?.Evidence.Status == VPetFamilyStatus.LimitReached && result.Decoded is null);
        int dataOffset = 1024 + 4 * 1024 * 1024, bodyLength = dataOffset + 512;
        byte[] expanded = new byte[bodyLength + 108]; good.AsSpan(0, 1024).CopyTo(expanded); good.AsSpan(2560, 108).CopyTo(expanded.AsSpan(bodyLength));
        V030U32(expanded, 0x188 + 40 + 8, 4 * 1024 * 1024); V030U32(expanded, 0x188 + 40 + 16, 4 * 1024 * 1024);
        uint dataRva = 8192 + 4 * 1024 * 1024;
        V030U32(expanded, 0x188 + 80 + 12, dataRva); V030U32(expanded, 0x188 + 80 + 20, (uint)dataOffset); V030U32(expanded, 152 + 56, dataRva + 4096);
        V030U32(expanded, bodyLength + 92, 4 * 1024 * 1024); V030U32(expanded, bodyLength + 96, dataRva);
        using (MemoryStream input = new(expanded, false))
        using (var result = await VPetFamilyDecoder.InspectAsync(input, Hashing.Sha256Bytes(expanded), default))
            Check("0.3 第4步 超过 4 MiB 数据区变换上限不分配派生输出", result?.Evidence.ReasonCode == "VPET-DECODE-LIMIT" && result.Decoded is null);
        using (MemoryStream input = new(good, false))
        using (CancellationTokenSource cancel = new())
        {
            ContainerResourceBudget budget = new(new(), cancel.Token) { Progress = () => { if (input.Position == 2560) cancel.Cancel(); } };
            bool cancelled = false;
            try { using var ignored = await VPetFamilyDecoder.InspectAsync(input, Hashing.Sha256Bytes(good), cancel.Token, budget); }
            catch (OperationCanceledException) { cancelled = true; }
            Check("0.3 第4步 解码过程中响应取消且不接受派生展开", cancelled && budget.AcceptedExpandedBytes == 0);
        }
        foreach (byte[] negative in new[] { "native VirtualAlloc .orig.dll"u8.ToArray(), V030InertEnvelope(false).Plain })
        {
            using MemoryStream input = new(negative, false);
            using var result = await VPetFamilyDecoder.InspectAsync(input, Hashing.Sha256Bytes(negative), default);
            Check("0.3 第4步 单独文件名字符串或普通 PE 不构成封装", result is null);
        }
        using (FileStream input = File.OpenRead(typeof(Program).Assembly.Location))
        using (var result = VPetWrapperInspector.Inspect(input, new string('A', 64), default))
            Check("0.3 第4步 正常托管程序集及普通互操作不会命中外壳组合", result is null);
        string malformedPath = Path.Combine(directory, "bad-footer.dat"); await File.WriteAllBytesAsync(malformedPath, malformed[8].Data);
        ScanReport partial = await new ScanCoordinator(new()).RunAsync(V030ContentOptions(malformedPath));
        Check("0.3 第4步 真实扫描对损坏封装保留 Partial 和未知尾部", partial.Coverage == ScanCoverage.Partial &&
            partial.Containers?.Nodes.Any(n => n.Kind == ContainerNodeKind.UnknownRange) == true && !partial.Findings.Any(f => f.IsKnownMalware || f.CanRemediate));
    }

    // Non-executable fixture: no imports, no entry point, all-zero code. Only headers and inert text are present.
    private static (byte[] Encoded, byte[] Plain) V030InertEnvelope(bool credential)
    {
        byte[] plain = new byte[2560]; plain[0] = (byte)'M'; plain[1] = (byte)'Z'; V030U32(plain, 60, 128);
        V030U32(plain, 128, 0x4550); BinaryPrimitives.WriteUInt16LittleEndian(plain.AsSpan(132), 0x8664);
        BinaryPrimitives.WriteUInt16LittleEndian(plain.AsSpan(134), 3); BinaryPrimitives.WriteUInt16LittleEndian(plain.AsSpan(148), 240);
        BinaryPrimitives.WriteUInt16LittleEndian(plain.AsSpan(150), 0x2002); BinaryPrimitives.WriteUInt16LittleEndian(plain.AsSpan(152), 0x20b);
        V030U32(plain, 152 + 32, 4096); V030U32(plain, 152 + 36, 512); V030U32(plain, 152 + 56, 16384);
        V030U32(plain, 152 + 60, 512); V030U32(plain, 152 + 108, 16); V030U32(plain, 152 + 112, 8192); V030U32(plain, 152 + 116, 96);
        Section(0, ".text", 4096, 512, 512, 0x60000020); Section(1, ".rdata", 8192, 1024, 1024, 0x40000040); Section(2, ".data", 12288, 2048, 512, 0xc0000040);
        V030U32(plain, 1024 + 12, 8256); V030U32(plain, 1024 + 16, 1); V030U32(plain, 1024 + 20, 1);
        V030U32(plain, 1024 + 28, 8240); V030U32(plain, 1072, 4096);
        Encoding.ASCII.GetBytes(credential ? "_2.bin" : "_1.bin").CopyTo(plain, 1088);
        string inert = credential ? "ReadProcessMemory CryptUnprotectData ConnectCache loginusers.vdf WinHttpSendRequest upload uid [VDF] https://luminovastella.top/" :
            "__pxS __pxH SupportMessages HelpFrontPage /*px:b*/ /*px:e*/ https://luminovastella.top/";
        Encoding.ASCII.GetBytes(inert).CopyTo(plain, 1152);
        byte[] encoded = new byte[plain.Length + 108]; plain.CopyTo(encoded, 0);
        for (int i = 0; i < 88; i++) encoded[plain.Length + i] = (byte)i;
        V030U32(encoded, 2560 + 88, 8192); V030U32(encoded, 2560 + 92, 1024);
        V030U32(encoded, 2560 + 96, 12288); V030U32(encoded, 2560 + 100, 512); V030U32(encoded, 2560 + 104, 104);
        // Independent fixture encoder; real sample outputs are also compared to frozen pre-implementation hashes.
        byte[] material = Enumerable.Range(0, 32).Select(i => (byte)((8 + i) ^ (40 + i))).Concat(Enumerable.Range(40, 48).Select(i => (byte)i)).ToArray();
        byte[] seed = SHA256.HashData(material);
        for (int p = 0; p < 1536; p += 32)
        {
            byte[] pad = SHA256.HashData(seed.Concat(BitConverter.GetBytes((uint)(p / 32))).ToArray());
            for (int j = 0; j < 32; j++) encoded[1024 + p + j] ^= pad[j];
        }
        return (encoded, plain);
        void Section(int index, string name, uint rva, uint offset, uint length, uint flags)
        {
            int p = 392 + index * 40; Encoding.ASCII.GetBytes(name).CopyTo(plain, p);
            V030U32(plain, p + 8, length); V030U32(plain, p + 12, rva); V030U32(plain, p + 16, length);
            V030U32(plain, p + 20, offset); V030U32(plain, p + 36, flags);
        }
    }
    private static void V030U32(byte[] bytes, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
}

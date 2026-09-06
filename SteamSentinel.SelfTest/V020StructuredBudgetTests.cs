using System.IO;
using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Rules;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV020StructuredBudgetAsync(string root)
    {
        string directory = Path.Combine(root, "v020-structured-budget"); Directory.CreateDirectory(directory);
        const string cabinetText = "SteamSentinel native CAB budget fixture: inert text only.";
        string cab = Path.Combine(directory, "inert-budget.cab");
        await File.WriteAllBytesAsync(cab, CreateStoredCabinet("../inert-budget.txt", cabinetText));
        long cabLength = new FileInfo(cab).Length, cabExpanded = Encoding.UTF8.GetByteCount(cabinetText);
        ContainerResourceLimits Limits(long work = 2 * 1024 * 1024, long temporary = 1024 * 1024,
            long expanded = 1024 * 1024, int metadata = 1000) => new()
            {
                MaximumEntryBytes = 1024 * 1024,
                MaximumExpandedBytes = expanded,
                MaximumWorkBytes = work,
                MaximumTemporaryBytes = temporary,
                ReservedDiskBytes = 0,
                MaximumMetadataAttempts = metadata
            };
        ContainerResourceBudget cabBudget = new(Limits());
        using (TemporaryDirectory temp = new())
        {
            StructuredInspection result = StructuredContainerInspector.ReadCabinet(cab, temp, 1024 * 1024,
                1024 * 1024, 16, default, cabBudget);
            ContainerResourceSnapshot used = cabBudget.Snapshot();
            Check("0.2.0 CAB原生读取与解码预留不混入实测字节",
                result.Members.Count == 1 && used.ReadBytes == 0 && used.DecodedBytes == 0 &&
                used.NativeReservedReadBytes == cabLength && used.NativeReservedDecodedBytes == cabExpanded &&
                used.AcceptedExpandedBytes == cabExpanded && await File.ReadAllTextAsync(result.Members[0].Path) == cabinetText);
            Check("0.2.0 CAB临时占用保留到递归消费结束", used.CurrentTemporaryBytes == cabExpanded && used.PeakTemporaryBytes == cabExpanded);
            result.Dispose(); temp.Dispose(); result.ReconcileTemporary();
            Check("0.2.0 CAB清理只退临时占用且不退原生工作预留",
                cabBudget.Snapshot().CurrentTemporaryBytes == 0 && cabBudget.Snapshot().NativeReservedDecodedBytes == cabExpanded);
        }

        ContainerResourceBudget cabWork = new(Limits(work: cabLength + cabExpanded - 1));
        using (TemporaryDirectory temp = new())
        {
            bool rejected = false;
            try { using StructuredInspection _ = StructuredContainerInspector.ReadCabinet(cab, temp, 1024 * 1024, 1024 * 1024, 16, default, cabWork); }
            catch (ScanResourceLimitException) { rejected = true; }
            Check("0.2.0 CAB共享工作超限穿过原生回调传播并不落盘",
                rejected && !Directory.EnumerateFiles(temp.Path).Any() && cabWork.Snapshot().CurrentTemporaryBytes == 0);
        }
        ContainerResourceBudget cabTemp = new(Limits(temporary: 1));
        using (TemporaryDirectory temp = new())
        {
            bool rejected = false;
            try { using StructuredInspection _ = StructuredContainerInspector.ReadCabinet(cab, temp, 1024 * 1024, 1024 * 1024, 16, default, cabTemp); }
            catch (ScanResourceLimitException) { rejected = true; }
            Check("0.2.0 CAB写入前拒绝临时预算不足且失败不退款工作",
                rejected && cabTemp.Snapshot().CurrentTemporaryBytes == 0 && cabTemp.Snapshot().NativeReservedDecodedBytes == cabExpanded);
        }
        using (CancellationTokenSource cancelled = new())
        using (TemporaryDirectory temp = new())
        {
            cancelled.Cancel(); ContainerResourceBudget budget = new(Limits(), cancelled.Token);
            bool propagated = false;
            try { using StructuredInspection _ = StructuredContainerInspector.ReadCabinet(cab, temp, 1024 * 1024, 1024 * 1024, 16, cancelled.Token, budget); }
            catch (OperationCanceledException) { propagated = true; }
            Check("0.2.0 结构化扫描取消不降格为普通注记", propagated && budget.Snapshot().NativeReservedReadBytes == 0);
        }

        byte[] payload = Enumerable.Range(0, 130 * 1024).Select(i => (byte)(i % 251)).ToArray();
        string source = Path.Combine(directory, "inert-stream.bin"); await File.WriteAllBytesAsync(source, payload);
        string msi = Path.Combine(directory, "inert-stream.msi");
        CreatePhase2MsiFixture(msi,
        [
            Phase2ActionSchema,
            "INSERT INTO `CustomAction` (`Action`,`Type`,`Source`,`Target`) VALUES ('inert',51,'FIXTURE','inert-budget-never-executed')",
            "CREATE TABLE `Binary` (`Name` CHAR(72) NOT NULL, `Data` OBJECT NOT NULL PRIMARY KEY `Name`)"
        ], database =>
        {
            uint record = Phase2MsiNative.CreateRecord(2), view = 0;
            if (record == 0) throw new IOException("Cannot create inert MSI stream record.");
            try
            {
                if (Phase2MsiNative.SetString(record, 1, "inert-budget") != 0 || Phase2MsiNative.SetStream(record, 2, source) != 0 ||
                    MsiFixture.View(database, "SELECT `Name`,`Data` FROM `Binary`", out view) != 0 || MsiFixture.Execute(view, 0) != 0 ||
                    Phase2MsiNative.Modify(view, 1, record) != 0) throw new IOException("Cannot insert inert MSI stream.");
            }
            finally { if (view != 0) MsiFixture.Close(view); MsiFixture.Close(record); }
        });
        long msiLength = new FileInfo(msi).Length;
        ContainerResourceBudget msiBudget = new(Limits());
        using (TemporaryDirectory temp = new())
        {
            StructuredInspection result = StructuredContainerInspector.ReadMsi(msi, temp, 1024 * 1024, 1024 * 1024, 16, default, msiBudget);
            ContainerResourceSnapshot used = msiBudget.Snapshot();
            Check("0.2.0 MSI原生元数据独立预留而成员流按多块实际计量",
                result.Members.Count == 1 && (await File.ReadAllBytesAsync(result.Members[0].Path)).SequenceEqual(payload) &&
                used.NativeReservedReadBytes == msiLength && used.NativeReservedDecodedBytes == 0 && used.ReadBytes == 0 &&
                used.DecodedBytes >= payload.Length && used.AcceptedExpandedBytes == payload.Length && used.CurrentTemporaryBytes == payload.Length);
            Check("0.2.0 MSI被过滤的Streams探测读取仍计入实际工作", used.DecodedBytes >= payload.Length + 64 * 1024);
            long charged = used.DecodedBytes;
            result.Dispose(); temp.Dispose(); result.ReconcileTemporary();
            Check("0.2.0 MSI清理释放临时占用且保留已发生流读取", msiBudget.Snapshot().CurrentTemporaryBytes == 0 && msiBudget.Snapshot().DecodedBytes == charged);
        }

        ContainerResourceBudget msiWork = new(Limits(work: msiLength + payload.Length - 1));
        using (TemporaryDirectory temp = new())
        {
            StructuredInspection retained = new(msiWork); bool rejected = false;
            try { StructuredContainerInspector.ReadMsi(msi, temp, 1024 * 1024, 1024 * 1024, 16, default, msiWork, retained); }
            catch (ScanResourceLimitException) { rejected = true; }
            finally { retained.Dispose(); temp.Dispose(); retained.ReconcileTemporary(); }
            Check("0.2.0 MSI逐块工作超限保留结构证据并清理部分输出",
                rejected && retained.Metadata.Any(text => text.Contains("inert-budget-never-executed")) &&
                msiWork.Snapshot().DecodedBytes == payload.Length - 1 && msiWork.Snapshot().AcceptedExpandedBytes == 0 &&
                msiWork.Snapshot().CurrentTemporaryBytes == 0);
        }
        ContainerResourceBudget msiRows = new(Limits(metadata: 1));
        using (TemporaryDirectory temp = new())
        {
            bool rejected = false;
            try { using StructuredInspection _ = StructuredContainerInspector.ReadMsi(msi, temp, 1024 * 1024, 1024 * 1024, 16, default, msiRows); }
            catch (ScanResourceLimitException) { rejected = true; }
            Check("0.2.0 MSI固定表行读取也受共享元数据尝试上限控制", rejected && msiRows.Snapshot().DecodedBytes == 0);
        }

        // Object limits must not terminate later roots, but a shared logical limit
        // must keep its exception even when the legacy caller also passes a limit.
        string laterRoot = Path.Combine(directory, "later-inert-root.txt");
        await File.WriteAllTextAsync(laterRoot, "SteamSentinel later root: inert text only.");
        RuleSet rules = RuleLoader.LoadEmbedded();
        foreach ((string format, string path, bool isCabinet, long expanded) in new[]
        {
            ("MSI", msi, false, (long)payload.Length),
            ("CAB", cab, true, cabExpanded)
        })
        {
            CheckLocalLimit(format + "单项", path, isCabinet, perEntry: 1, remaining: 1024 * 1024);
            CheckLocalLimit(format + "局部剩余量", path, isCabinet, perEntry: 1024 * 1024, remaining: 1);

            ContainerResourceBudget logical = new(Limits(expanded: expanded - 1));
            using (TemporaryDirectory temp = new())
            {
                StructuredInspection retained = new(logical); bool rejected = false;
                try { Inspect(path, isCabinet, temp, 1024 * 1024, 1024 * 1024, logical, retained); }
                catch (ScanResourceLimitException) { rejected = true; }
                finally { retained.Dispose(); temp.Dispose(); retained.ReconcileTemporary(); }
                Check($"0.2.0 {format}共享逻辑展开超限必须传播且失败成员不计入接受量",
                    rejected && logical.AcceptedExpandedBytes == 0 && logical.Snapshot().CurrentTemporaryBytes == 0);
            }

            ScanReport localReport = new();
            bool localEscaped = false;
            using (ContentScanner scanner = new(rules))
            {
                ScanOptions options = Options(perEntry: 1, Limits());
                try
                {
                    await scanner.ScanRootAsync(path, localReport, options, new NullPasswordProvider());
                    await scanner.ScanRootAsync(laterRoot, localReport, options, new NullPasswordProvider());
                }
                catch (ScanResourceLimitException) { localEscaped = true; }
            }
            Check($"0.2.0 {format}单项超限保留缺口并继续同轮后续普通根",
                !localEscaped && localReport.RootSummaries.Count == 2 &&
                localReport.RootSummaries[0].Coverage == ScanCoverage.Partial &&
                localReport.RootSummaries[1].Path == laterRoot && localReport.RootSummaries[1].FilesVisited == 1 &&
                localReport.Findings.Any(finding => finding.RuleId == "INSTALLER-PARTIAL"));

            ScanReport sharedReport = new();
            bool sharedEscaped = false;
            using (ContentScanner scanner = new(rules))
            {
                try
                {
                    await scanner.ScanRootAsync(path, sharedReport,
                        Options(perEntry: 1024 * 1024, Limits(expanded: expanded - 1)), new NullPasswordProvider());
                }
                catch (ScanResourceLimitException) { sharedEscaped = true; }
            }
            Check($"0.2.0 {format}扫描调用方不能把共享逻辑限额钳成局部注记",
                sharedEscaped && sharedReport.Coverage == ScanCoverage.Partial &&
                sharedReport.Containers is { } containers &&
                containers.Nodes.Any(node => node.Overall == ContainerStageStatus.LimitReached) &&
                containers.Resources.AcceptedExpandedBytes == 0 && containers.Resources.CurrentTemporaryBytes == 0);
        }
        CheckLocalLimit("MSI写完首个64KiB后单项", msi, false, perEntry: 64 * 1024, remaining: 1024 * 1024,
            requirePartialRead: true);
        CheckLocalLimit("MSI写完首个64KiB后局部剩余量", msi, false, perEntry: 1024 * 1024, remaining: 64 * 1024,
            requirePartialRead: true);

        void CheckLocalLimit(string label, string path, bool isCabinet, long perEntry, long remaining,
            bool requirePartialRead = false)
        {
            ContainerResourceBudget budget = new(Limits());
            using TemporaryDirectory temp = new();
            StructuredInspection retained = new(budget); bool globalFailure = false;
            try { Inspect(path, isCabinet, temp, perEntry, remaining, budget, retained); }
            catch (ScanResourceLimitException) { globalFailure = true; }
            finally { retained.Dispose(); temp.Dispose(); retained.ReconcileTemporary(); }
            ContainerResourceSnapshot used = budget.Snapshot();
            Check($"0.2.0 {label}限制保留注记且不接纳或保留部分成员",
                !globalFailure && retained.Members.Count == 0 && retained.ExpandedBytes == 0 &&
                retained.Notes.Any(note => note.Contains("上限")) &&
                (isCabinet || retained.Metadata.Any(text => text.Contains("inert-budget-never-executed"))) &&
                used.AcceptedExpandedBytes == 0 && used.CurrentTemporaryBytes == 0 &&
                (!requirePartialRead || used.DecodedBytes >= 2 * 64 * 1024 && used.PeakTemporaryBytes == 64 * 1024));
        }

        static StructuredInspection Inspect(string path, bool cabinet, TemporaryDirectory temp, long perEntry,
            long remaining, ContainerResourceBudget budget, StructuredInspection result) => cabinet
            ? StructuredContainerInspector.ReadCabinet(path, temp, perEntry, remaining, 16, default, budget, result)
            : StructuredContainerInspector.ReadMsi(path, temp, perEntry, remaining, 16, default, budget, result);

        static ScanOptions Options(long perEntry, ContainerResourceLimits limits) => new()
        {
            IncludeSystem = false,
            IncludeSteam = false,
            IncludeWorkshop = false,
            UseAmsi = false,
            Mode = ScanMode.Full,
            InspectDeepSignatures = false,
            MaximumEntryBytes = perEntry,
            MaximumExpandedBytes = 1024 * 1024,
            ContainerLimits = limits
        };
    }
}

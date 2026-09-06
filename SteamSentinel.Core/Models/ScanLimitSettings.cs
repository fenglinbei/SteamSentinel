using System.Text.Json;
using System.Text.Json.Nodes;

namespace SteamSentinel.Core.Models;

/// <summary>User-owned budgets. Missing fields retain versioned defaults; values are never silently clamped.</summary>
public sealed class ScanLimitSettings
{
    public int SchemaVersion { get; set; } = 1;
    public Dictionary<string, decimal> Quick { get; set; } = [];
    public Dictionary<string, decimal> Full { get; set; } = [];

    public Dictionary<string, decimal> For(ScanMode mode) => mode == ScanMode.Quick ? Quick : Full;

    public static IReadOnlyList<string> Presets { get; } = ["较低", "低", "中", "高", "极高", "自定义"];

    public static string PresetDescription(int index) => index switch
    {
        0 => "较低：资源占用较少，适合小范围初查；大文件、深层归档更容易留下未检查内容。",
        1 => "低：减少读取、解压与等待预算；覆盖范围可能小于默认设置。",
        2 => "中：当前版本默认预算，兼顾检查范围与资源占用。",
        3 => "高：扩大文件、深度和时间预算；会使用更多内存与临时磁盘，扫描可能明显变慢。",
        4 => "极高：面向大型、复杂内容；可能长时间占用磁盘与 CPU、耗尽可用空间或内存。请结合本机资源使用。",
        _ => "自定义：逐项决定预算。各项限制同时生效，调高一项不代表其他限制也已解除。"
    };

    public void UsePreset(ScanMode mode, int index)
    {
        if (index is < 0 or > 4) throw new ArgumentOutOfRangeException(nameof(index));
        Dictionary<string, decimal> values = For(mode);
        values.Clear();
        decimal factor = new[] { 0.25m, 0.5m, 1m, 4m, 16m }[index];
        foreach (ScanLimitDefinition field in Fields)
        {
            decimal value = field.Default(mode) * factor;
            if (field.Scale == 1) value = Math.Max(1, decimal.Floor(value));
            value = field.Key switch
            {
                "ContainerLimits.MaximumDepth" => mode == ScanMode.Quick ? new[] { 1, 2, 4, 8, 16 }[index] : new[] { 2, 6, 12, 24, 64 }[index],
                "MaximumWorkerMemoryBytes" => new[] { 512, 768, 1024, 2048, 4096 }[index],
                "ContainerLimits.ReservedDiskBytes" => new[] { 2048, 1536, 1024, 512, 256 }[index],
                "ContainerLimits.MaximumDurationSeconds" => mode == ScanMode.Quick ? new[] { 60, 180, 300, 1200, 3600 }[index] : new[] { 300, 900, 1800, 7200, 21600 }[index],
                "MaximumContentBytes" when mode != ScanMode.Quick => new[] { 8192, 16384, 0, 0, 0 }[index],
                _ => value
            };
            field.Validate(value);
            if (value != field.Default(mode)) values[field.Key] = value;
        }
    }

    public int DetectPreset(ScanMode mode)
    {
        for (int index = 0; index < 5; index++)
        {
            ScanLimitSettings candidate = new(); candidate.UsePreset(mode, index);
            if (Fields.All(field => For(mode).GetValueOrDefault(field.Key, field.Default(mode)) ==
                candidate.For(mode).GetValueOrDefault(field.Key, field.Default(mode)))) return index;
        }
        return 5;
    }

    public void Validate()
    {
        if (SchemaVersion != 1 || Quick is null || Full is null)
            throw new InvalidDataException("扫描设置版本或内容无效。");
        foreach (var profile in new[] { Quick, Full })
            foreach (var pair in profile)
            {
                ScanLimitDefinition field = Fields.SingleOrDefault(f => f.Key == pair.Key)
                    ?? throw new InvalidDataException("无法识别扫描设置项：" + pair.Key);
                field.Validate(pair.Value);
            }
    }

    public ScanOptions Apply(ScanOptions source)
    {
        Validate();
        JsonObject json = JsonSerializer.SerializeToNode(source)!.AsObject();
        json[nameof(ScanOptions.ContainerLimits)] = new JsonObject();
        json[nameof(ScanOptions.RangeLimits)] = new JsonObject();
        foreach (ScanLimitDefinition field in Fields)
        {
            decimal value = For(source.Mode).GetValueOrDefault(field.Key, field.Default(source.Mode));
            field.Validate(value);
            string[] path = field.Key.Split('.');
            JsonObject target = path.Length == 1 ? json : json[path[0]]!.AsObject();
            decimal native = field.Key == "MaximumContentBytes" && value == 0 ? long.MaxValue : value * field.Scale;
            target[path[^1]] = JsonValue.Create((long)native);
        }
        // Legacy and graph readers must use the same effective budgets.
        var limits = json[nameof(ScanOptions.ContainerLimits)]!.AsObject();
        json[nameof(ScanOptions.MaximumEntryBytes)] = limits[nameof(ContainerResourceLimits.MaximumEntryBytes)]!.DeepClone();
        json[nameof(ScanOptions.MaximumExpandedBytes)] = limits[nameof(ContainerResourceLimits.MaximumExpandedBytes)]!.DeepClone();
        json[nameof(ScanOptions.MaximumArchiveDepth)] = limits[nameof(ContainerResourceLimits.MaximumDepth)]!.DeepClone();
        json[nameof(ScanOptions.MaximumArchiveEntries)] = limits[nameof(ContainerResourceLimits.MaximumEntries)]!.DeepClone();
        json[nameof(ScanOptions.MaximumCompressionRatio)] = limits[nameof(ContainerResourceLimits.MaximumCompressionRatio)]!.DeepClone();
        json[nameof(ScanOptions.RangeLimits)]![nameof(ContainerRangeLimits.MaximumDuration)] =
            JsonSerializer.SerializeToNode(TimeSpan.FromSeconds((double)json[nameof(ScanOptions.MaximumStructureDurationSeconds)]!.GetValue<long>()));
        return json.Deserialize<ScanOptions>()!;
    }

    private const decimal MiB = 1048576;
    private const decimal BytesMaximum = (long.MaxValue - 1048576) / MiB;
    private const decimal CountMaximum = int.MaxValue - 1;
    private static ScanLimitDefinition Bytes(string key, string label, decimal quick, decimal full, string effect,
        bool zero = false, decimal? maximum = null) => new(key, label, "MiB", quick, full, zero ? 0 : 1 / MiB,
            maximum ?? BytesMaximum, MiB, effect, zero);
    private static ScanLimitDefinition Count(string key, string label, decimal quick, decimal full, string effect,
        string unit = "个", decimal maximum = CountMaximum) => new(key, label, unit, quick, full, 1, maximum, 1, effect);

    public static IReadOnlyList<ScanLimitDefinition> Fields { get; } =
    [
        Bytes("MaximumContentBytes", "整轮文件哈希预算", 1024, 0, "调高会读取更多文件、增加磁盘耗时；调低会留下未哈希内容。0 表示不设该项总量限制。", true),
        Bytes("MaximumQuickFileBytes", "快速扫描单文件读取", 256, 256, "仅快速扫描使用。调高能读取更大文件；调低会跳过大文件的完整哈希。"),
        Bytes("MaximumQuickPriorityBytes", "快速扫描启动文件额外预算", 128, 128, "普通哈希预算用尽后使用。调高会延长快速扫描；调低可能漏查后续启动文件。", true),
        Bytes("MaximumQuickPriorityFileBytes", "快速扫描优先文件大小", 8, 8, "仅小于此值的启动文件可用额外预算；调高会让少数大文件占用更多预算。"),
        Count("MaximumFiles", "文件／目录遍历数量", 200000, 200000, "调高能覆盖更大目录树，耗时和结果量增加；调低会提前结束遍历。"),
        Bytes("MaximumStringScanBytes", "单文件字符串与行为检查", 32, 32, "调高可分析大文件正文，增加读取和计算时间；调低会跳过超限正文。"),
        Bytes("MaximumAmsiBytes", "单文件 AMSI 提交大小", 32, 32, "AMSI 需要整块内存。调高显著增加内存占用，可能被本机引擎拒绝或耗尽内存；调低会跳过超限内容。", maximum: Array.MaxLength / MiB),
        Bytes("MaximumWorkerMemoryBytes", "扫描进程内存预算", 1024, 1024, "接近此值时尝试停止并保留结果。调高可能耗尽系统内存；调低可能连扫描组件都无法启动。"),
        Count("MaximumReportRecords", "每类报告记录数量", 20000, 20000, "调高允许保留更多结果，但增加界面和报告内存；调低会提前停止内容检查。", maximum: int.MaxValue - 257),
        new("MaximumReportTextCharacters", "报告累计文本量", "字符", 8388608, 8388608, 1, long.MaxValue - 1048576, 1, "调高增加报告与界面内存占用；调低可能因路径或证据文字过多而停止。"),
        Bytes("ContainerLimits.MaximumEntryBytes", "单个解压成员大小", 256, 8192, "调高可展开大文件，也允许更大的异常归档消耗资源；调低会跳过大成员。"),
        Bytes("ContainerLimits.MaximumExpandedBytes", "整轮累计接受展开量", 2048, 32768, "嵌套的每层内容均计入。调高增加磁盘与计算量；调低可能在深层内容之前用尽。"),
        Bytes("ContainerLimits.MaximumWorkBytes", "整轮累计读取与解码量", 4096, 65536, "重复读取、哈希、解码和失败尝试均计入，通常大于展开量。调高更耗时；调低会中断检查。"),
        Bytes("ContainerLimits.MaximumTemporaryBytes", "临时文件同时占用", 2048, 16384, "调高可能占满临时盘；调低会阻止多层或大型归档展开。"),
        Bytes("ContainerLimits.ReservedDiskBytes", "临时盘保留空闲空间", 1024, 1024, "调高会更早停止展开；调低能使用更多磁盘，但可能影响系统和其他程序。0 表示不主动预留。", true),
        Count("ContainerLimits.MaximumDepth", "归档嵌套深度", 4, 12, "调高能检查更深层嵌套，也会增加耗时、内存和调用栈压力；调低会留下深层内容。", "层"),
        Count("ContainerLimits.MaximumEntries", "解压成员数量", 20000, 20000, "调高能处理成员更多的归档；调低会停止处理剩余成员。还需为容器节点预留数量。"),
        Count("ContainerLimits.MaximumNodes", "容器结果节点数量", 20000, 20000, "外层、分段和每层成员都占节点。调高增加报告大小与内存；调低会提前停止。"),
        Count("ContainerLimits.MaximumMetadataAttempts", "归档目录读取尝试", 80000, 80000, "调高允许更多目录枚举与重试；调低可能在正文解码前用尽预算。", "次"),
        Count("ContainerLimits.MaximumPasswordAttempts", "密码解码累计尝试", 512, 512, "调高允许更多解密尝试，错误密码也消耗时间；调低会更早停止重试。", "次"),
        Count("ContainerLimits.MaximumVolumes", "分卷文件数量", 128, 128, "调高可读取更多分卷；调低会把未纳入的卷记录为未检查。"),
        Count("ContainerLimits.MaximumDirectoryCandidates", "分卷目录候选数量", 4096, 4096, "调高增加目录读取时间；调低可能找不到排在后面的分卷。"),
        Count("ContainerLimits.MaximumDurationSeconds", "内容扫描时间", 300, 1800, "调高允许慢盘或复杂归档运行更久；调低会提前停止。到时保留已完成结果，取消按钮始终可用。", "秒", 4294960),
        Count("ContainerLimits.MaximumCompressionRatio", "允许的压缩比", 500, 500, "调高可处理高度重复的数据，也更容易消耗大量资源；调低会跳过正常的高压缩率内容。", "倍", long.MaxValue),
        Count("MaximumStructureDurationSeconds", "单文件容器结构检查时间", 15, 15, "调高允许复杂结构检查更久；调低可能在确认边界前停止。整轮时间预算仍然生效。", "秒", 4294960),
        Bytes("RangeLimits.MaximumReadBytes", "单文件容器结构读取量", 32, 32, "调高增加 MP4／自解压结构读取范围；调低可能无法识别完整边界。"),
        Bytes("RangeLimits.MaximumSignatureSearchBytes", "容器标记搜索范围", 4, 4, "调高可搜索更大自解压前导区域；调低可能找不到嵌入内容。", maximum: (int.MaxValue - 1) / MiB),
        Count("RangeLimits.MaximumCandidates", "容器候选区域数量", 128, 128, "调高增加验证次数；调低可能遗漏后续候选区域。"),
        Count("RangeLimits.MaximumRecords", "容器结构记录数量", 100000, 100000, "调高支持复杂媒体或归档结构；调低会提前停止结构检查。"),
        Count("RangeLimits.MaximumZipEntries", "ZIP 结构条目数量", 100000, 100000, "调高增加结构检查时间；调低可能无法确认大型 ZIP 的边界。"),
        Bytes("RangeLimits.MaximumHeaderBytes", "容器单头部大小", 2, 2, "调高可读取更大的容器头，也增加内存占用；调低可能拒绝正常头部。", maximum: (int.MaxValue - 1) / MiB),
        Bytes("RangeLimits.MaximumSfxConfigurationBytes", "自解压配置大小", 0.25m, 0.25m, "调高可读取更多自解压配置并增加内存；调低会留下未读取配置。", maximum: (int.MaxValue - 1) / MiB)
    ];
}

public sealed record ScanLimitDefinition(string Key, string Label, string Unit, decimal QuickDefault,
    decimal FullDefault, decimal Minimum, decimal Maximum, decimal Scale, string Consequence, bool UnlimitedZero = false)
{
    public decimal Default(ScanMode mode) => mode == ScanMode.Quick ? QuickDefault : FullDefault;
    public void Validate(decimal value)
    {
        if (value < Minimum || value > Maximum || decimal.Truncate(value * Scale) != value * Scale)
            throw new InvalidDataException($"{Label}：请输入 {Minimum:0.########} 到 {Maximum:0.########} {Unit}，换算后必须是整数{(Scale == 1 ? "" : "字节")}。");
    }
}

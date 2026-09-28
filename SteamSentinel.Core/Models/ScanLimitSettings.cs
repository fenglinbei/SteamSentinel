using SteamSentinel.Core.Reporting;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SteamSentinel.Core.Models;

/// <summary>User-owned budgets. Missing fields retain versioned defaults; values are never silently clamped.</summary>
public sealed class ScanLimitSettings
{
    public int SchemaVersion { get; set; } = 1;
    public Dictionary<string, decimal> Quick { get; set; } = [];
    public Dictionary<string, decimal> Full { get; set; } = [];
    public bool AskBeforeIncreasing { get; set; } = true;
    public ScanPerformanceMode PerformanceMode { get; set; } = ScanPerformanceMode.Automatic;

    public Dictionary<string, decimal> For(ScanMode mode) => mode == ScanMode.Quick ? Quick : Full;

    public static IReadOnlyList<string> Presets => [DisplayText.Get("ScanLimitSettings.Presets.01"), DisplayText.Get("ScanLimitSettings.Presets.02"), DisplayText.Get("ScanLimitSettings.Presets.03"), DisplayText.Get("ScanLimitSettings.Presets.04"), DisplayText.Get("ScanLimitSettings.Presets.05"), DisplayText.Get("ScanLimitSettings.Presets.06")];

    public static string PresetDescription(int index) => index switch
    {
        0 => DisplayText.Get("ScanLimitSettings.PresetDescription.01"),
        1 => DisplayText.Get("ScanLimitSettings.PresetDescription.02"),
        2 => DisplayText.Get("ScanLimitSettings.PresetDescription.03"),
        3 => DisplayText.Get("ScanLimitSettings.PresetDescription.04"),
        4 => DisplayText.Get("ScanLimitSettings.PresetDescription.05"),
        _ => DisplayText.Get("ScanLimitSettings.PresetDescription.06")
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
        if (SchemaVersion != 1 || Quick is null || Full is null || !Enum.IsDefined(PerformanceMode))
            throw new InvalidDataException(DisplayText.Get("ScanLimitSettings.Validate.01"));
        foreach (var profile in new[] { Quick, Full })
            foreach (var pair in profile)
            {
                ScanLimitDefinition field = Fields.SingleOrDefault(f => f.Key == pair.Key)
                    ?? throw new InvalidDataException(DisplayText.Get("ScanLimitSettings.Validate.02") + pair.Key);
                field.Validate(pair.Value);
            }
    }

    public ScanOptions Apply(ScanOptions source)
    {
        Validate();
        JsonObject json = JsonSerializer.SerializeToNode(source)!.AsObject();
        json[nameof(ScanOptions.AllowResourceDecisions)] = AskBeforeIncreasing;
        json[nameof(ScanOptions.PerformanceMode)] = (int)PerformanceMode;
        json[nameof(ScanOptions.MaximumParallelFiles)] = PerformanceMode == ScanPerformanceMode.LowImpact ? 1 : 4;
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
        string? unit = null, decimal maximum = CountMaximum) => new(key, label, unit ?? DisplayText.Get("ScanLimitSettings.Count.01"), quick, full, 1, maximum, 1, effect);

    private static readonly Lazy<IReadOnlyList<ScanLimitDefinition>> ChineseFields = new(() => CreateFields(DisplayText.Chinese));
    private static readonly Lazy<IReadOnlyList<ScanLimitDefinition>> EnglishFields = new(() => CreateFields(DisplayText.English));
    public static IReadOnlyList<ScanLimitDefinition> Fields => DisplayText.Culture.Name == "zh-Hans" ? ChineseFields.Value : EnglishFields.Value;

    private static IReadOnlyList<ScanLimitDefinition> CreateFields(System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return
    [
        Bytes("MaximumContentBytes", DisplayText.Get("ScanLimitSettings.Fields.01"), 1024, 0, DisplayText.Get("ScanLimitSettings.Fields.02"), true),
        Bytes("MaximumQuickFileBytes", DisplayText.Get("ScanLimitSettings.Fields.03"), 256, 256, DisplayText.Get("ScanLimitSettings.Fields.04")),
        Bytes("MaximumQuickPriorityBytes", DisplayText.Get("ScanLimitSettings.Fields.05"), 128, 128, DisplayText.Get("ScanLimitSettings.Fields.06"), true),
        Bytes("MaximumQuickPriorityFileBytes", DisplayText.Get("ScanLimitSettings.Fields.07"), 8, 8, DisplayText.Get("ScanLimitSettings.Fields.08")),
        Count("MaximumFiles", DisplayText.Get("ScanLimitSettings.Fields.09"), 200000, 200000, DisplayText.Get("ScanLimitSettings.Fields.10")),
        Bytes("MaximumStringScanBytes", DisplayText.Get("ScanLimitSettings.Fields.11"), 32, 32, DisplayText.Get("ScanLimitSettings.Fields.12")),
        Bytes("MaximumAmsiBytes", DisplayText.Get("ScanLimitSettings.Fields.13"), 32, 32, DisplayText.Get("ScanLimitSettings.Fields.14"), maximum: Array.MaxLength / MiB),
        Bytes("MaximumWorkerMemoryBytes", DisplayText.Get("ScanLimitSettings.Fields.15"), 1024, 1024, DisplayText.Get("ScanLimitSettings.Fields.16")),
        Count("MaximumReportRecords", DisplayText.Get("ScanLimitSettings.Fields.17"), 20000, 20000, DisplayText.Get("ScanLimitSettings.Fields.18"), maximum: int.MaxValue - 257),
        new("MaximumReportTextCharacters", DisplayText.Get("ScanLimitSettings.Fields.19"), DisplayText.Get("ScanLimitSettings.Fields.20"), 8388608, 8388608, 1, long.MaxValue - 1048576, 1, DisplayText.Get("ScanLimitSettings.Fields.21")),
        Bytes("ContainerLimits.MaximumEntryBytes", DisplayText.Get("ScanLimitSettings.Fields.22"), 256, 8192, DisplayText.Get("ScanLimitSettings.Fields.23")),
        Bytes("ContainerLimits.MaximumExpandedBytes", DisplayText.Get("ScanLimitSettings.Fields.24"), 2048, 32768, DisplayText.Get("ScanLimitSettings.Fields.25")),
        Bytes("ContainerLimits.MaximumWorkBytes", DisplayText.Get("ScanLimitSettings.Fields.26"), 4096, 65536, DisplayText.Get("ScanLimitSettings.Fields.27")),
        Bytes("ContainerLimits.MaximumTemporaryBytes", DisplayText.Get("ScanLimitSettings.Fields.28"), 2048, 16384, DisplayText.Get("ScanLimitSettings.Fields.29")),
        Bytes("ContainerLimits.ReservedDiskBytes", DisplayText.Get("ScanLimitSettings.Fields.30"), 1024, 1024, DisplayText.Get("ScanLimitSettings.Fields.31"), true),
        Count("ContainerLimits.MaximumDepth", DisplayText.Get("ScanLimitSettings.Fields.32"), 4, 12, DisplayText.Get("ScanLimitSettings.Fields.33"), DisplayText.Get("ScanLimitSettings.Fields.34")),
        Count("ContainerLimits.MaximumEntries", DisplayText.Get("ScanLimitSettings.Fields.35"), 20000, 20000, DisplayText.Get("ScanLimitSettings.Fields.36")),
        Count("ContainerLimits.MaximumNodes", DisplayText.Get("ScanLimitSettings.Fields.37"), 20000, 20000, DisplayText.Get("ScanLimitSettings.Fields.38")),
        Count("ContainerLimits.MaximumMetadataAttempts", DisplayText.Get("ScanLimitSettings.Fields.39"), 80000, 80000, DisplayText.Get("ScanLimitSettings.Fields.40"), DisplayText.Get("ScanLimitSettings.Fields.41")),
        Count("ContainerLimits.MaximumPasswordAttempts", DisplayText.Get("ScanLimitSettings.Fields.42"), 512, 512, DisplayText.Get("ScanLimitSettings.Fields.43"), DisplayText.Get("ScanLimitSettings.Fields.44")),
        Count("ContainerLimits.MaximumVolumes", DisplayText.Get("ScanLimitSettings.Fields.45"), 128, 128, DisplayText.Get("ScanLimitSettings.Fields.46")),
        Count("ContainerLimits.MaximumDirectoryCandidates", DisplayText.Get("ScanLimitSettings.Fields.47"), 4096, 4096, DisplayText.Get("ScanLimitSettings.Fields.48")),
        Count("ContainerLimits.MaximumDurationSeconds", DisplayText.Get("ScanLimitSettings.Fields.49"), 300, 1800, DisplayText.Get("ScanLimitSettings.Fields.50"), DisplayText.Get("ScanLimitSettings.Fields.51"), 4294960),
        Count("ContainerLimits.MaximumCompressionRatio", DisplayText.Get("ScanLimitSettings.Fields.52"), 500, 500, DisplayText.Get("ScanLimitSettings.Fields.53"), DisplayText.Get("ScanLimitSettings.Fields.54"), long.MaxValue),
        Count("MaximumStructureDurationSeconds", DisplayText.Get("ScanLimitSettings.Fields.55"), 15, 15, DisplayText.Get("ScanLimitSettings.Fields.56"), DisplayText.Get("ScanLimitSettings.Fields.57"), 4294960),
        Bytes("RangeLimits.MaximumReadBytes", DisplayText.Get("ScanLimitSettings.Fields.58"), 32, 32, DisplayText.Get("ScanLimitSettings.Fields.59")),
        Bytes("RangeLimits.MaximumSignatureSearchBytes", DisplayText.Get("ScanLimitSettings.Fields.60"), 4, 4, DisplayText.Get("ScanLimitSettings.Fields.61"), maximum: (int.MaxValue - 1) / MiB),
        Count("RangeLimits.MaximumCandidates", DisplayText.Get("ScanLimitSettings.Fields.62"), 128, 128, DisplayText.Get("ScanLimitSettings.Fields.63")),
        Count("RangeLimits.MaximumRecords", DisplayText.Get("ScanLimitSettings.Fields.64"), 100000, 100000, DisplayText.Get("ScanLimitSettings.Fields.65")),
        Count("RangeLimits.MaximumZipEntries", DisplayText.Get("ScanLimitSettings.Fields.66"), 100000, 100000, DisplayText.Get("ScanLimitSettings.Fields.67")),
        Bytes("RangeLimits.MaximumHeaderBytes", DisplayText.Get("ScanLimitSettings.Fields.68"), 2, 2, DisplayText.Get("ScanLimitSettings.Fields.69"), maximum: (int.MaxValue - 1) / MiB),
        Bytes("RangeLimits.MaximumSfxConfigurationBytes", DisplayText.Get("ScanLimitSettings.Fields.70"), 0.25m, 0.25m, DisplayText.Get("ScanLimitSettings.Fields.71"), maximum: (int.MaxValue - 1) / MiB)
    ];
    }
}

public sealed record ScanLimitDefinition(string Key, string Label, string Unit, decimal QuickDefault,
    decimal FullDefault, decimal Minimum, decimal Maximum, decimal Scale, string Consequence, bool UnlimitedZero = false)
{
    public decimal Default(ScanMode mode) => mode == ScanMode.Quick ? QuickDefault : FullDefault;
    public void Validate(decimal value)
    {
        if (value < Minimum || value > Maximum || decimal.Truncate(value * Scale) != value * Scale)
            throw new InvalidDataException(DisplayText.Format("ScanLimitSettings.Validate.03", (Label), (Minimum), (Maximum), (Unit), ((Scale == 1 ? "" : DisplayText.Get("ScanLimitSettings.Validate.04")))));
    }
}

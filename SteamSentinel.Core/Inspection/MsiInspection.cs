using SteamSentinel.Core.Reporting;
namespace SteamSentinel.Core.Inspection;

// Internal parse objects never cross the report/IPC boundary. Reports use the bounded
// summary produced by MsiActionAnalyzer, not attacker-controlled installation tables.
internal enum MsiReadState { Complete, Absent, Failed, LimitReached, NotChecked }
[method: System.Text.Json.Serialization.JsonConstructor]
internal sealed record MsiTableRead(string Table, MsiReadState State, int Rows, string Detail = "")
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public MsiTableRead(string Table, MsiReadState State, int Rows, SteamSentinel.Core.Reporting.MessageText Detail) : this(Table, State, Rows, Detail.OriginalText)
    {
        DetailMessage = Detail.Message;
    }
}
internal sealed record MsiProperty(string Name, string Value);
internal sealed record MsiDirectory(string Id, string Parent, string DefaultDir);
internal sealed record MsiComponent(string Id, string Directory, string Condition, string KeyPath);
internal sealed record MsiFile(string Id, string Component, string Name, long? Size, int? Sequence);
internal sealed record MsiMedia(int? DiskId, int? LastSequence, string Cabinet);
internal sealed record MsiCustomAction(string Action, int? Type, string Source, string Target);
internal sealed record MsiSequence(string Table, string Action, string Condition, int? Sequence);
internal sealed record MsiRegistry(string Id, int? Root, string Key, string Name, string Value, string Component);
internal sealed record MsiShortcut(string Id, string Directory, string Name, string Component, string Target, string Arguments, string WorkingDirectory);
internal sealed record MsiServiceInstall(string Id, string Name, int? ServiceType, int? StartType, string Arguments, string Component);
internal sealed record MsiServiceControl(string Id, string Name, int? Event, string Arguments, string Component);

internal sealed class MsiInspection
{
    internal bool Recognized { get; set; }
    internal List<MsiTableRead> Tables { get; } = [];
    internal List<MsiProperty> Properties { get; } = [];
    internal List<MsiDirectory> Directories { get; } = [];
    internal List<MsiComponent> Components { get; } = [];
    internal List<MsiFile> Files { get; } = [];
    internal List<MsiMedia> Media { get; } = [];
    internal List<MsiCustomAction> Actions { get; } = [];
    internal List<MsiSequence> Sequences { get; } = [];
    internal List<MsiRegistry> Registry { get; } = [];
    internal List<MsiShortcut> Shortcuts { get; } = [];
    internal List<MsiServiceInstall> Services { get; } = [];
    internal List<MsiServiceControl> ServiceControls { get; } = [];
    internal HashSet<string> BinaryNames { get; } = new(StringComparer.Ordinal);
    internal int ReadRows => Tables.Sum(t => t.Rows);
}

internal sealed class MsiActionAnalysis
{
    internal MessageTextCollection Evidence { get; } = [];
    internal MessageTextCollection CoverageGaps { get; } = [];
    internal MessageTextCollection ContentSignals { get; } = [];
    internal MessageTextCollection LinkedSignals { get; } = [];
    internal int ActionCount { get; set; }
}

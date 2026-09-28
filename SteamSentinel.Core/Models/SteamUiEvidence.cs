using SteamSentinel.Core.Reporting;
namespace SteamSentinel.Core.Models;

public sealed record SteamUiEvidenceFile(string RelativePath, string Sha256, IReadOnlyList<string> Signals);
public sealed class SteamUiEvidence
{
    public string DetectorId { get; init; } = "VPET-STEAMUI-20260919-1";
    public bool EntryReferenceVerified { get; init; }
    public bool SupportRoutesLinked { get; init; }
    public bool ActivationGateObserved { get; init; }
    public List<SteamUiEvidenceFile> Files { get; init; } = [];
    public List<string> Signals { get; init; } = [];

    internal void Validate()
    {
        if (string.IsNullOrWhiteSpace(DetectorId) || DetectorId.Length > 64 || Files is null || Files.Count is < 1 or > 8 || Signals is null || Signals.Count > 32 ||
            Signals.Any(s => string.IsNullOrWhiteSpace(s) || s.Length > 128) || Files.Any(file => file is null ||
                string.IsNullOrWhiteSpace(file.RelativePath) || file.RelativePath.Length > 4096 || file.RelativePath.StartsWith('/') ||
                file.RelativePath.Contains(':') || file.RelativePath.Contains('\\') || file.RelativePath.Any(char.IsControl) || file.RelativePath.Split('/').Any(part => part is ".." or "." or "") ||
                !Utilities.Validation.IsHexSha256(file.Sha256) || file.Signals is null || file.Signals.Count > 16 ||
                file.Signals.Any(s => string.IsNullOrWhiteSpace(s) || s.Length > 128)))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.SteamUiEvidence.Validate.01"), sourceText => new InvalidDataException(sourceText));
        if (Files.Select(file => file.RelativePath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != Files.Count)
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.SteamUiEvidence.Validate.02"), sourceText => new InvalidDataException(sourceText));
    }
}

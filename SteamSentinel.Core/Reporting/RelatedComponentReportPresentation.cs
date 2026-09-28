using System.Text;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

/// <summary>Bounded, read-only presentation. Observation links never grant remediation eligibility.</summary>
public static class RelatedComponentReportPresentation
{
    public static string Describe(RelatedComponentDiagnosticReport diagnostic, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return Describe(diagnostic);
    }

    public static string Summary(RelatedComponentDiagnosticReport diagnostic, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return Summary(diagnostic);
    }

    public static string DescribeFinding(Finding finding, RelatedComponentDiagnosticReport? diagnostic, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return DescribeFinding(finding, diagnostic);
    }

    public static string EvidenceTierLabel(RelatedEvidenceTier? tier, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return EvidenceTierLabel(tier);
    }

    public static string StatusLabel(DiagnosticReadStatus status, System.Globalization.CultureInfo culture)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return StatusLabel(status);
    }

    public const string SourceKind = "related-components";
    public const int MaximumDescriptionCharacters = 256_000;
    private const int MaximumListedRecords = 1024;
    private static string OmissionNotice => DisplayText.Get("RelatedComponentReport.OmissionNotice.01");

    public static bool IsRelatedFinding(Finding finding) =>
        finding.AssociationObservationIds.Count > 0 || finding.SourceKind == SourceKind || finding.AssociationEvidenceTier is not null;

    public static string EvidenceTierLabel(RelatedEvidenceTier? tier) => tier switch
    {
        RelatedEvidenceTier.Observation => DisplayText.Get("RelatedComponentReport.EvidenceTierLabel.Observation.01"),
        RelatedEvidenceTier.RelatedRisk => DisplayText.Get("RelatedComponentReport.EvidenceTierLabel.RelatedRisk.01"),
        RelatedEvidenceTier.ConfirmedTarget => DisplayText.Get("RelatedComponentReport.EvidenceTierLabel.ConfirmedTarget.01"),
        _ => DisplayText.Get("RelatedComponentReport.EvidenceTierLabel.01")
    };

    public static string StatusLabel(DiagnosticReadStatus status) => status switch
    {
        DiagnosticReadStatus.Complete => DisplayText.Get("RelatedComponentReport.StatusLabel.Complete.01"),
        DiagnosticReadStatus.NotPresent => DisplayText.Get("RelatedComponentReport.StatusLabel.NotPresent.01"),
        DiagnosticReadStatus.NotChecked => DisplayText.Get("RelatedComponentReport.StatusLabel.NotChecked.01"),
        DiagnosticReadStatus.AccessDenied => DisplayText.Get("RelatedComponentReport.StatusLabel.AccessDenied.01"),
        DiagnosticReadStatus.LimitReached => DisplayText.Get("RelatedComponentReport.StatusLabel.LimitReached.01"),
        DiagnosticReadStatus.Cancelled => DisplayText.Get("RelatedComponentReport.StatusLabel.Cancelled.01"),
        DiagnosticReadStatus.Failed => DisplayText.Get("RelatedComponentReport.StatusLabel.01"),
        _ => DisplayText.Get("Common.Unknown")
    };

    public static string Summary(RelatedComponentDiagnosticReport diagnostic)
    {
        bool incomplete = diagnostic.Checks.Any(check => check.Required && IsIncomplete(check.Status)) ||
            diagnostic.Rounds.Any(round => round.CompletedAtUtc is null || IsIncomplete(round.Status)) ||
            diagnostic.Sources.Any(source => IsIncomplete(source.Status)) || diagnostic.Hosts.Any(host => IsIncomplete(host.Status)) ||
            diagnostic.Candidates.Any(candidate => IsIncomplete(candidate.Status));
        string state = diagnostic.CompletedAtUtc is null ? DisplayText.Get("RelatedComponentReport.Summary.01")
            : incomplete ? DisplayText.Get("RelatedComponentReport.Summary.02")
            : diagnostic.Candidates.Any(candidate => IsIncomplete(candidate.ContentStatus)) ? DisplayText.Get("RelatedComponentReport.Summary.03")
            : diagnostic.Checks.Count + diagnostic.Rounds.Count == 0 ? DisplayText.Get("RelatedComponentReport.Summary.04") : DisplayText.Get("RelatedComponentReport.Summary.05");
        return DisplayText.Format("RelatedComponentReport.Summary.06", (state), (diagnostic.Sources.Count), (diagnostic.Hosts.Count), (diagnostic.Candidates.Count));
    }

    public static string Describe(RelatedComponentDiagnosticReport diagnostic)
    {
        BoundedText text = new(MaximumDescriptionCharacters);
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.01"));
        text.Line(Summary(diagnostic));
        text.Line(DisplayText.Format("RelatedComponentReport.Describe.02", (Display(diagnostic.TargetUserSid))));
        text.Line(DisplayText.Format("RelatedComponentReport.Describe.03", (diagnostic.StartedAtUtc), (Time(diagnostic.CompletedAtUtc))));
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.04"));
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.05"));
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.06"));
        text.Line();
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.07"));
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.08"));
        if (diagnostic.AppliedLimits is { } limits)
        {
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.09", (limits.MaximumRounds), (Bytes(limits.MaximumTotalBytes)), (Bytes(limits.MaximumFileBytes)), (limits.MaximumCandidates), (limits.MaximumHosts)));
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.10", (limits.MaximumDiscoveryDuration.TotalSeconds), (limits.MaximumDuration.TotalSeconds)));
        }
        else text.Line(DisplayText.Get("RelatedComponentReport.Describe.11"));
        foreach (RelatedScanRound round in diagnostic.Rounds.Take(16))
        {
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.12", (round.Number), (StatusLabel(round.Status)), (Bytes(round.BytesRead)), ((round.MaximumBytes is long budget ? Bytes(budget) : DisplayText.Get("RelatedComponentReport.Describe.13"))), (round.CandidateIds.Count)));
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.14", (round.StartedAtUtc), (Time(round.CompletedAtUtc)), (Display(round.DetailText.Display))));
            text.Line(DisplayText.Get("RelatedComponentReport.Describe.15") + References(round.CandidateIds));
        }
        if (diagnostic.Rounds.Count == 0) text.Line(DisplayText.Get("RelatedComponentReport.Describe.16"));
        if (diagnostic.Rounds.Count > 16) text.Omitted();

        RelatedSourceObservation[] sources = diagnostic.Sources.Take(MaximumListedRecords).ToArray();
        RelatedHostObservation[] hosts = diagnostic.Hosts.Take(MaximumListedRecords).ToArray();
        RelatedComponentCandidate[] candidates = diagnostic.Candidates.Take(MaximumListedRecords).ToArray();
        text.Line();
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.17"));
        foreach (RelatedSourceObservation source in sources)
        {
            if (text.Full) break;
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.18", (StatusLabel(source.Status)), (Display(source.Kind)), (Display(source.Scope)), (Display(source.Id))));
            text.Line(DisplayText.Get("RelatedComponentReport.Describe.19") + Display(source.Location));
            text.Line(DisplayText.Get("RelatedComponentReport.Describe.20") + Display(source.RawCommand));
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.21", (Display(source.WorkingDirectory)), (Display(source.UserSid))));
            text.Line(DisplayText.Get("RelatedComponentReport.Describe.22") + References(source.ResolvedTargets));
            text.Line(DisplayText.Get("RelatedComponentReport.Describe.23") + Display(source.DetailText.Display));
            RelatedHostObservation[] linkedHosts = hosts.Where(host => host.SourceObservationIds.Contains(source.Id)).Take(16).ToArray();
            RelatedComponentCandidate[] linkedCandidates = candidates.Where(candidate => candidate.SourceObservationIds.Contains(source.Id)).Take(16).ToArray();
            foreach (RelatedHostObservation host in linkedHosts)
            {
                RelatedComponentCandidate[] modules = candidates.Where(candidate => candidate.HostObservationIds.Contains(host.Id)).Take(16).ToArray();
                if (modules.Length == 0) text.Line(DisplayText.Format("RelatedComponentReport.Describe.24", (Display(source.Id)), (host.ProcessId), (Display(host.ImagePath))));
                foreach (RelatedComponentCandidate candidate in modules)
                    text.Line(DisplayText.Format("RelatedComponentReport.Describe.25", (Display(source.Id)), (host.ProcessId), (Display(candidate.Path)), (Display(candidate.Id))));
                if (candidates.Count(candidate => candidate.HostObservationIds.Contains(host.Id)) > modules.Length) text.Omitted();
            }
            foreach (RelatedComponentCandidate candidate in linkedCandidates.Where(candidate =>
                !candidate.HostObservationIds.Any(id => linkedHosts.Any(host => host.Id == id))))
                text.Line(DisplayText.Format("RelatedComponentReport.Describe.26", (Display(source.Id)), (Display(candidate.Path)), (Display(candidate.Id))));
            if (hosts.Count(host => host.SourceObservationIds.Contains(source.Id)) > linkedHosts.Length ||
                candidates.Count(candidate => candidate.SourceObservationIds.Contains(source.Id)) > linkedCandidates.Length) text.Omitted();
        }

        text.Line();
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.27"));
        foreach (RelatedHostObservation host in hosts)
        {
            if (text.Full) break;
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.28", (StatusLabel(host.Status)), (host.ProcessId), (Display(host.Id))));
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.29", (Display(host.ImagePath)), (Time(host.StartedAtUtc))));
            text.Line(DisplayText.Get("RelatedComponentReport.Describe.30") + Display(host.ImageSha256));
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.31", (Display(host.CommandLine)), (Display(host.WorkingDirectory))));
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.32", (SignatureLabel(host.SignatureStatus)), (Display(host.SignatureDetailText.Display))));
            text.Line(DisplayText.Get("RelatedComponentReport.Describe.33") + References(host.SourceObservationIds));
            text.Line(DisplayText.Get("RelatedComponentReport.Describe.34") + Display(host.DetailText.Display));
        }

        text.Line();
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.35"));
        foreach (RelatedComponentCandidate candidate in candidates)
        {
            if (text.Full) break;
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.36", (StatusLabel(candidate.Status)), (Display(candidate.Path)), (Display(candidate.Id))));
            text.Line(DisplayText.Get("RelatedComponentReport.Describe.37") + Display(candidate.ReasonText.Display));
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.38", (Display(candidate.Sha256)), ((candidate.Length is long size ? Bytes(size) : DisplayText.Get("RelatedComponentReport.Describe.39"))), (Time(candidate.VerifiedAtUtc))));
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.40", (StatusLabel(candidate.ContentStatus)), (Display(candidate.ContentDetailText.Display))));
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.41", (References(candidate.SourceObservationIds)), (References(candidate.HostObservationIds))));
            text.Line(DisplayText.Get("RelatedComponentReport.Describe.42") + References(candidate.EvidenceObservationIds));
            text.Line(DisplayText.Get("RelatedComponentReport.Describe.43") + Display(candidate.DetailText.Display));
        }
        if (diagnostic.Sources.Count > sources.Length || diagnostic.Hosts.Count > hosts.Length || diagnostic.Candidates.Count > candidates.Length) text.Omitted();

        text.Line();
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.44"));
        foreach (DiagnosticRelation relation in diagnostic.Relations.Take(4096))
        {
            if (text.Full) break;
            text.Line(DisplayText.Format("Common.LabelValue", $"{Display(relation.FromId)} → {Display(relation.ToId)} · {Display(relation.Kind)}", Display(relation.EvidenceText.Display)));
        }
        if (diagnostic.Relations.Count > 4096) text.Omitted();
        text.Line();
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.45"));
        foreach (DiagnosticCheck check in diagnostic.Checks.Take(MaximumListedRecords))
        {
            if (text.Full) break;
            text.Line(DisplayText.Format("RelatedComponentReport.Describe.46", (StatusLabel(check.Status)), (Display(check.NameText.Display)), ((check.Required ? "" : DisplayText.Get("RelatedComponentReport.Describe.47"))), (Display(check.DetailText.Display)), (Display(check.ObservationId))));
        }
        if (diagnostic.Checks.Count > MaximumListedRecords) text.Omitted();
        text.Line(DisplayText.Get("RelatedComponentReport.Describe.48"));
        return text.ToString();
    }

    public static string DescribeFinding(Finding finding, RelatedComponentDiagnosticReport? diagnostic)
    {
        if (!IsRelatedFinding(finding)) return string.Empty;
        BoundedText text = new(12_000);
        text.Line(DisplayText.Get("RelatedComponentReport.DescribeFinding.01"));
        text.Line(DisplayText.Format("Related.TierExplanation", EvidenceTierLabel(finding.AssociationEvidenceTier)));
        text.Line(DisplayText.Get("RelatedComponentReport.DescribeFinding.04"));
        if (diagnostic is null) text.Line(DisplayText.Get("RelatedComponentReport.DescribeFinding.05"));
        else foreach (string id in finding.AssociationObservationIds.Distinct(StringComparer.Ordinal).Take(16))
        {
            RelatedComponentCandidate? candidate = diagnostic.Candidates.FirstOrDefault(item => item.Id == id);
            RelatedHostObservation? host = diagnostic.Hosts.FirstOrDefault(item => item.Id == id);
            RelatedSourceObservation? source = diagnostic.Sources.FirstOrDefault(item => item.Id == id);
            DiagnosticCheck? check = diagnostic.Checks.FirstOrDefault(item => item.Id == id);
            if (candidate is not null)
            {
                text.Line(DisplayText.Format("RelatedComponentReport.DescribeFinding.06", (Display(id)), (Display(candidate.Path)), (Display(candidate.ReasonText.Display)), (StatusLabel(candidate.ContentStatus)), (Display(candidate.ContentDetailText.Display))));
                text.Line(DisplayText.Format("RelatedComponentReport.DescribeFinding.07", (Display(candidate.Sha256)), (Time(candidate.VerifiedAtUtc))));
            }
            else if (host is not null)
                text.Line(DisplayText.Format("RelatedComponentReport.DescribeFinding.08", (Display(id)), (host.ProcessId), (Display(host.ImagePath)), (Time(host.StartedAtUtc)), (StatusLabel(host.Status)), (Display(host.DetailText.Display))));
            else if (source is not null)
                text.Line(DisplayText.Format("RelatedComponentReport.DescribeFinding.09", (Display(id)), (Display(source.Kind)), (Display(source.Location)), (StatusLabel(source.Status)), (Display(source.DetailText.Display))));
            else if (check is not null)
                text.Line(DisplayText.Format("RelatedComponentReport.DescribeFinding.10", (Display(id)), (Display(check.NameText.Display)), (StatusLabel(check.Status)), (Display(check.DetailText.Display))));
            else text.Line(DisplayText.Format("RelatedComponentReport.DescribeFinding.11", (Display(id))));
        }
        if (finding.AssociationObservationIds.Count > 16) text.Omitted();
        text.Line(DisplayText.Get("RelatedComponentReport.DescribeFinding.12"));
        return text.ToString();
    }

    private static bool IsIncomplete(DiagnosticReadStatus status) => status is not (DiagnosticReadStatus.Complete or DiagnosticReadStatus.NotPresent);
    private static string SignatureLabel(string status) => status switch
    {
        "Valid" => DisplayText.Get("RelatedComponentReport.SignatureLabel.01"),
        "Unsigned" => DisplayText.Get("RelatedComponentReport.SignatureLabel.02"),
        "Failed" => DisplayText.Get("RelatedComponentReport.SignatureLabel.03"),
        "NotChecked" => DisplayText.Get("RelatedComponentReport.SignatureLabel.04"),
        _ => Display(status)
    };
    private static string Time(DateTimeOffset? value) => value?.ToString("O") ?? DisplayText.Get("RelatedComponentReport.Time.01");
    private static string Bytes(long value) => DisplayText.Format("RelatedComponentReport.Bytes.01", (value));
    private static string References(IReadOnlyList<string> values) => values.Count == 0 ? DisplayText.Get("RelatedComponentReport.References.01") :
        string.Join(DisplayText.Get("Common.Semicolon"), values.Take(16).Select(Display)) + (values.Count > 16 ? DisplayText.Format("RelatedComponentReport.References.02", (values.Count - 16)) : "");
    private static string Display(string? value) => string.IsNullOrEmpty(value) ? DisplayText.Get("RelatedComponentReport.Display.01") :
        value.Length > 32768 ? DisplayText.Get("RelatedComponentReport.Display.02") :
        ScriptSignals.Redact(value).Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");

    private sealed class BoundedText(int maximum)
    {
        private readonly StringBuilder _text = new();
        private bool _omitted;
        public bool Full { get; private set; }
        public void Omitted() => _omitted = true;
        public void Line(string value = "")
        {
            if (Full) return;
            int remaining = maximum - OmissionNotice.Length - _text.Length - Environment.NewLine.Length;
            if (value.Length > remaining)
            {
                if (remaining > 0) _text.Append(value.AsSpan(0, remaining));
                Full = true; _omitted = true;
                return;
            }
            _text.AppendLine(value);
        }
        public override string ToString() => _text.ToString() + (_omitted ? OmissionNotice : string.Empty);
    }
}

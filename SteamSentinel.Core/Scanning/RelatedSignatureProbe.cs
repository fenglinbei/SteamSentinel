using SteamSentinel.Core.Reporting;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Scanning;

/// <summary>Exact-file offline signature observations for the restricted content worker only.</summary>
public sealed class RelatedSignatureProbe
{
    public const int MaximumPaths = 32;
    public const long MaximumFileBytes = 16L * 1024 * 1024;
    public const string RuleId = "ASSOCIATION-HOST-SIGNATURE";
    private readonly Func<string, SafeFileHandle, SignatureResult> _verify;

    public RelatedSignatureProbe() : this((path, handle) => AuthenticodeVerifier.VerifyOffline(path, handle)) { }
    internal RelatedSignatureProbe(Func<string, SafeFileHandle, SignatureResult> verify) => _verify = verify;

    public async Task CollectAsync(ScanReport report, IReadOnlyList<string> paths, long maximumBytes,
        CancellationToken token, Action<ScanReport>? checkpoint = null)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(paths);
        long consumed = 0;
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        string[] bounded = paths.Take(MaximumPaths).ToArray();
        if (paths.Count > MaximumPaths)
            Partial(MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.01", (MaximumPaths)));
        if (maximumBytes < 0)
            Partial(MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.02"));

        for (int index = 0; index < bounded.Length; index++)
        {
            string raw = bounded[index] ?? string.Empty;
            string path = raw;
            string? sha256 = null;
            long hashBytes = 0, trustReserve = 0;
            try
            {
                token.ThrowIfCancellationRequested();
                if (raw.Length > 32768 || !ContentDiscovery.IsLocalSafePath(raw))
                {
                    Observe("NotChecked", MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.03"));
                    continue;
                }
                path = Path.GetFullPath(raw);
                if (!seen.Add(path)) continue;
                string extension = Path.GetExtension(path);
                if (!extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                    !extension.Equals(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    Observe("NotChecked", MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.04"));
                    continue;
                }
                if (maximumBytes <= consumed)
                {
                    Observe("NotChecked", MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.05"));
                    continue;
                }

                await using FileStream stream = RelatedArtifactReader.Open(path);
                long length = stream.Length;
                if (length > MaximumFileBytes || length > (maximumBytes - consumed) / 2)
                {
                    Observe("NotChecked", MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.06", (length), (MaximumFileBytes)));
                    continue;
                }
                sha256 = await Hashing.Sha256StreamAsync(stream, token, bytes =>
                {
                    hashBytes += bytes;
                    consumed += bytes;
                    report.Metrics.BytesHashed += bytes;
                }, maximumBytes: length).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, path);
                stream.Position = 0;
                // WinTrust does not expose actual I/O bytes. Charge one additional full
                // file length conservatively before entering the native verification call.
                trustReserve = length;
                consumed += trustReserve;
                report.Metrics.BytesHashed += trustReserve;
                SignatureResult result = _verify(path, stream.SafeFileHandle);
                token.ThrowIfCancellationRequested();
                RelatedArtifactReader.ValidatePath(stream.SafeFileHandle, path);
                Observe(result.Status switch
                {
                    SignatureStatus.Valid => "Valid",
                    SignatureStatus.Unsigned => "Unsigned",
                    _ => "Failed"
                }, result.DetailText);
            }
            catch (OperationCanceledException)
            {
                Observe("NotChecked", MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.07"));
                for (int rest = index + 1; rest < bounded.Length; rest++)
                {
                    path = bounded[rest] ?? string.Empty;
                    if (!seen.Add(path)) continue;
                    sha256 = null; hashBytes = 0; trustReserve = 0;
                    Observe("NotChecked", MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.08"));
                }
                throw;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Observe("Failed", MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.09") + MessageExceptions.Describe(ex));
            }
            finally
            {
                // Worker resource/output failures must leave this probe unchanged,
                // rather than being reclassified as a signature error.
                checkpoint?.Invoke(report);
            }

            void Observe(string status, MessageText detail)
            {
                DateTimeOffset observedAtUtc = DateTimeOffset.UtcNow;
                if (status is not ("Valid" or "Unsigned")) Partial(MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.10") + Short(path, 1024) + "；" + Short(detail, 1024));
                report.Findings.Add(new Finding
                {
                    RuleId = RuleId,
                    SourceKind = "related-components",
                    Category = FindingCategory.File,
                    Severity = FindingSeverity.Information,
                    Score = 0,
                    TitleText = MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.11"),
                    Target = Short(path, 32768),
                    Sha256 = sha256,
                    TargetSha256 = sha256,
                    ConfigurationKind = status,
                    CanRemediate = false,
                    IsKnownMalware = false,
                    DetectedAtUtc = observedAtUtc,
                    AssociationEvidenceTier = RelatedEvidenceTier.Observation,
                    SuggestedActions = [SuggestedActionKind.None],
                    DescriptionText = Short(detail, 2048) + MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.12"),
                    EvidenceText = MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.13", (System.FormattableString.Invariant($"{observedAtUtc:O}")), (hashBytes), (trustReserve)) +
                        MessageText.Create("Backend.Core.RelatedSignatureProbe.CollectAsync.14")
                });
            }
        }
        checkpoint?.Invoke(report);

        void Partial(MessageText detail)
        {
            report.Coverage = ScanCoverage.Partial;
            if (report.CoverageNotes.Count < 256 && !report.CoverageNotes.Contains(detail.OriginalText)) report.AddCoverageNote(detail);
        }
    }

    private static MessageText Short(MessageText value, int limit) => value.OriginalText.Length <= limit ? value : new(value.OriginalText[..limit] + "…");
}

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
            Partial($"宿主离线签名只接收前 {MaximumPaths} 个精确文件路径，其他宿主未检查。");
        if (maximumBytes < 0)
            Partial("宿主离线签名字节预算无效，未开始读取。");

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
                    Observe("NotChecked", "未取得安全、明确的本地文件路径；未读取内容。");
                    continue;
                }
                path = Path.GetFullPath(raw);
                if (!seen.Add(path)) continue;
                string extension = Path.GetExtension(path);
                if (!extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                    !extension.Equals(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    Observe("NotChecked", "离线宿主签名只检查精确的 EXE 或 DLL 文件，未读取其他类型。");
                    continue;
                }
                if (maximumBytes <= consumed)
                {
                    Observe("NotChecked", "宿主离线签名字节预算已用尽或不可用，未读取此文件。");
                    continue;
                }

                await using FileStream stream = RelatedArtifactReader.Open(path);
                long length = stream.Length;
                if (length > MaximumFileBytes || length > (maximumBytes - consumed) / 2)
                {
                    Observe("NotChecked", $"文件长度 {length} 字节超过单文件 {MaximumFileBytes} 字节上限，或剩余预算不足以预留两份文件长度；未读取正文。");
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
                }, result.Detail);
            }
            catch (OperationCanceledException)
            {
                Observe("NotChecked", "宿主离线签名检查已取消；保留此前完成的观察，此文件未获得完成状态。");
                for (int rest = index + 1; rest < bounded.Length; rest++)
                {
                    path = bounded[rest] ?? string.Empty;
                    if (!seen.Add(path)) continue;
                    sha256 = null; hashBytes = 0; trustReserve = 0;
                    Observe("NotChecked", "宿主离线签名检查已取消，未读取此文件。");
                }
                throw;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Observe("Failed", "宿主离线签名未完成（文件可能被占用、无权读取、已变化或不可用）：" + ex.Message);
            }
            finally
            {
                // Worker resource/output failures must leave this probe unchanged,
                // rather than being reclassified as a signature error.
                checkpoint?.Invoke(report);
            }

            void Observe(string status, string detail)
            {
                DateTimeOffset observedAtUtc = DateTimeOffset.UtcNow;
                if (status is not ("Valid" or "Unsigned")) Partial("宿主离线签名未完成：" + Short(path, 1024) + "；" + Short(detail, 1024));
                report.Findings.Add(new Finding
                {
                    RuleId = RuleId,
                    SourceKind = "related-components",
                    Category = FindingCategory.File,
                    Severity = FindingSeverity.Information,
                    Score = 0,
                    Title = "宿主离线签名观察",
                    Target = Short(path, 32768),
                    Sha256 = sha256,
                    TargetSha256 = sha256,
                    ConfigurationKind = status,
                    CanRemediate = false,
                    IsKnownMalware = false,
                    DetectedAtUtc = observedAtUtc,
                    AssociationEvidenceTier = RelatedEvidenceTier.Observation,
                    SuggestedActions = [SuggestedActionKind.None],
                    Description = Short(detail, 2048) + "；仅核验该路径现存磁盘文件，不读取或证明进程内存映像。仅使用本地信任与缓存，未联网、未进行吊销检查，不能据此认定恶意或文件安全。",
                    Evidence = $"观察记录时间：{observedAtUtc:O}。读取边界：SHA-256 与 Authenticode 只允许共用只读身份句柄；哈希实际读取 {hashBytes} 字节，WinTrust 额外预留 {trustReserve} 字节。" +
                        " WinTrust 不提供实际读取计数；两部分作为保守逻辑预算合计记入 BytesHashed，不代表原生调用实际 I/O。"
                });
            }
        }
        checkpoint?.Invoke(report);

        void Partial(string detail)
        {
            report.Coverage = ScanCoverage.Partial;
            if (report.CoverageNotes.Count < 256 && !report.CoverageNotes.Contains(detail)) report.CoverageNotes.Add(detail);
        }
    }

    private static string Short(string value, int limit) => value.Length <= limit ? value : value[..limit] + "…";
}

using SteamSentinel.Core.Models;

namespace SteamSentinel.App.ViewModels;

public sealed class QuarantineItemViewModel
{
    public required QuarantineManifest Manifest { get; init; }
    public required string ManifestPath { get; init; }
    public string? ReadError { get; init; }
    public string IncidentId => Manifest.IncidentId.ToString("D");
    public string Created => Manifest.CreatedAtUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public int ItemCount => Manifest.Records.Count;
    public int ActiveCount => Manifest.Records.Count(record => !record.RolledBack);
    public string Status => ReadError ?? (ActiveCount == 0 ? "已回滚/仅记录" : $"隔离中：{ActiveCount} 项");
    public bool RebootObserved
    {
        get
        {
            DateTimeOffset currentBoot = DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
            return currentBoot > Manifest.MachineBootTimeUtc.AddMinutes(1);
        }
    }
}

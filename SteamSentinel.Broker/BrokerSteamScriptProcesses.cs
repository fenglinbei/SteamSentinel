using System.ComponentModel;
using System.Diagnostics;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Broker;

internal sealed partial class BrokerEngine
{
    // Narrow by executable name before limited-query inspection. Protected, unrelated
    // system processes are never used as a reason to block an otherwise exact repair.
    internal static IReadOnlyList<RelatedProcessRead> ReadSteamScriptSourceProcesses(IEnumerable<string> sourcePaths)
    {
        string[] paths = sourcePaths.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        List<RelatedProcessRead> result = [];
        HashSet<int> seen = [];
        foreach (string name in paths.Where(path => Path.GetExtension(path).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                     .Select(path => Path.GetFileNameWithoutExtension(path)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            Process[] candidates = Process.GetProcessesByName(name);
            try
            {
                foreach (Process candidate in candidates)
                {
                    if (!seen.Add(candidate.Id)) continue;
                    RelatedProcessRead observation = RelatedComponentDiscovery.ProbeProcess(candidate.Id);
                    // A readable different path is unrelated even if the filename matches.
                    if (!string.IsNullOrEmpty(observation.ImagePath) && !paths.Any(path => PathsEquivalent(path, observation.ImagePath)))
                        continue;
                    try { if (candidate.HasExited) continue; }
                    catch (InvalidOperationException) { continue; }
                    catch (Win32Exception ex)
                    {
                        result.Add(observation with
                        {
                            Status = DiagnosticReadStatus.Failed,
                            DetailText = observation.DetailText + " " + MessageExceptions.Describe(ex)
                        });
                        continue;
                    }
                    result.Add(observation);
                }
            }
            finally { foreach (Process candidate in candidates) candidate.Dispose(); }
        }
        return result;
    }

    internal static void RequireSteamScriptProcessDependencies(RemediationPlan plan,
        IReadOnlyDictionary<string, string> verifiedSources, IEnumerable<RelatedProcessRead> observations)
    {
        RemediationAction[] repairs = plan.Actions.Where(action => action.Type == RemediationActionType.RepairSteamScript).ToArray();
        if (repairs.Length == 0) return;
        var dependencies = RemediationDependencies.Build(plan.Actions);
        foreach (RelatedProcessRead observation in RelevantScriptProcesses(verifiedSources.Keys, observations))
        {
            string sourceHash = verifiedSources.First(pair => PathsEquivalent(pair.Key, observation.ImagePath)).Value;
            RemediationAction? stop = plan.Actions.FirstOrDefault(action => action.Type == RemediationActionType.StopProcess &&
                action.ProcessId == observation.ProcessId && action.ProcessStartedAtUtc == observation.StartedAtUtc &&
                PathsEquivalent(action.Target, observation.ImagePath) &&
                string.Equals(action.ExpectedSha256, sourceHash, StringComparison.OrdinalIgnoreCase));
            if (stop is null || repairs.Any(repair => !dependencies[repair.ActionId].Contains(stop.ActionId)))
                throw ScriptDenied("SteamScript.Unconfirmed");
        }
    }

    internal static void RequireSteamScriptProcessesStopped(IEnumerable<string> paths, IEnumerable<RelatedProcessRead> observations)
    {
        if (RelevantScriptProcesses(paths, observations).Any()) throw ScriptDenied("SteamScript.Unconfirmed");
    }

    private static IEnumerable<RelatedProcessRead> RelevantScriptProcesses(IEnumerable<string> sourcePaths,
        IEnumerable<RelatedProcessRead> observations)
    {
        string[] paths = sourcePaths.ToArray();
        foreach (RelatedProcessRead observation in observations)
        {
            if (!string.IsNullOrEmpty(observation.ImagePath) &&
                !paths.Any(path => PathsEquivalent(path, observation.ImagePath))) continue;
            if (observation.Status != DiagnosticReadStatus.Complete || observation.StartedAtUtc is null ||
                string.IsNullOrEmpty(observation.ImagePath))
                throw MessageExceptions.Create(MessageText.Create("SteamScript.VerificationUnavailable") + " " + observation.DetailText,
                    text => new InvalidOperationException(text));
            yield return observation;
        }
    }
}

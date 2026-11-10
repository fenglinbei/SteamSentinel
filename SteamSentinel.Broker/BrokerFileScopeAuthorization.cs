using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

internal sealed record VerifiedBrokerFileTarget(Guid ActionId, RemediationActionType Type, string Target,
    string Sha256, string FileIdentity, string ParentIdentity, bool Sensitive, bool RequiresExplicitAuthorization,
    BrokerFileMetadata? Metadata);

/// <summary>
/// A Broker-computed snapshot. Constructing it is read-only and does not authorize execution;
/// BrokerEngine only installs it after the ordinary final confirmation succeeds.
/// </summary>
internal sealed class BrokerFileScopeAuthorization
{
    private readonly Guid _planId;
    private readonly string _planIdentity;
    private readonly Dictionary<Guid, VerifiedBrokerFileTarget> _targets;
    private int _state; // 0 = prepared; 1 = confirmed; 2 = execution attempted.

    private BrokerFileScopeAuthorization(RemediationPlan plan, Dictionary<Guid, VerifiedBrokerFileTarget> targets)
    { _planId = plan.PlanId; _planIdentity = RemediationPlanIdentity.Fingerprint(plan); _targets = targets; }

    internal IReadOnlyCollection<VerifiedBrokerFileTarget> Targets => _targets.Values;
    internal bool NeedsFullMetadata(RemediationAction action) =>
        _targets.TryGetValue(action.ActionId, out VerifiedBrokerFileTarget? target) && target.Metadata is not null;

    internal static async Task<BrokerFileScopeAuthorization> PrepareAsync(RemediationPlan plan,
        RuleSet rules, SteamLayout layout, CancellationToken token)
    {
        if (!plan.ExplicitFileTargetsRequested) throw BrokerScopeText.Denied(BrokerScopeText.NotAuthorized);
        Dictionary<Guid, VerifiedBrokerFileTarget> targets = [];
        foreach (RemediationAction action in plan.Actions.Where(IsFileAction))
        {
            token.ThrowIfCancellationRequested();
            if (!FileScopeSafety.IsValidIdentity(action.ExpectedFileIdentity) ||
                !FileScopeSafety.IsValidIdentity(action.ExpectedParentIdentity) || !Validation.IsHexSha256(action.ExpectedSha256))
                throw BrokerScopeText.Invalid(BrokerScopeText.InvalidIdentity);
            RequireSafePath(action.Target);
            using BrokerDirectoryLease parent = BrokerDirectoryLease.OpenParent(action.Target, action.ExpectedParentIdentity);
            await using SecureFileLease lease = SecureFileLease.Open(action.Target);
            string identity = RequireIdentity(lease, action.ExpectedFileIdentity!);
            string hash = await lease.ComputeSha256Async(token);
            if (!hash.Equals(action.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                throw BrokerScopeText.Invalid(BrokerScopeText.IdentityChanged);
            bool sensitive = FileScopeSafety.EvaluatePath(lease.FinalPath).Sensitive;
            bool requiresExplicit = sensitive || !FileRemediationScope.IsAllowed(lease.FinalPath, hash, rules, layout);
            BrokerFileMetadata? metadata = null;
            if (action.Type == RemediationActionType.QuarantineFile)
            {
                try { metadata = BrokerFileMetadata.Capture(lease.Handle, lease.FinalPath); }
                catch (System.ComponentModel.Win32Exception ex) when (!requiresExplicit && ex.NativeErrorCode is 5 or 1300 or 1314)
                {
                    // Some machines remove SeSecurityPrivilege from administrators. Existing automatic
                    // scope keeps its legacy restore behavior; expanded/sensitive scope never degrades.
                }
            }
            targets.Add(action.ActionId, new(action.ActionId, action.Type, lease.FinalPath, hash, identity,
                parent.ParentIdentity, sensitive, requiresExplicit, metadata));
        }
        return new(plan, targets);
    }

    internal void RequirePlan(RemediationPlan plan)
    {
        if (!plan.ExplicitFileTargetsRequested || plan.PlanId != _planId ||
            !RemediationPlanIdentity.Fingerprint(plan).Equals(_planIdentity, StringComparison.Ordinal))
            throw BrokerScopeText.Denied(BrokerScopeText.NotAuthorized);
    }

    internal void ConfirmOnce(RemediationPlan plan)
    {
        RequirePlan(plan);
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
            throw BrokerScopeText.Denied(BrokerScopeText.NotAuthorized);
    }

    internal void BeginExecution(RemediationPlan plan)
    {
        RequirePlan(plan);
        if (Interlocked.CompareExchange(ref _state, 2, 1) != 1)
            throw BrokerScopeText.Denied(BrokerScopeText.NotAuthorized);
    }

    internal bool Contains(RemediationAction action, string path, string? hash)
    {
        return _targets.TryGetValue(action.ActionId, out VerifiedBrokerFileTarget? verified) &&
            action.Type == verified.Type && IsFileAction(action) &&
            SamePath(path, verified.Target) && SamePath(action.Target, verified.Target) &&
            string.Equals(hash, verified.Sha256, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(action.ExpectedFileIdentity, verified.FileIdentity, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(action.ExpectedParentIdentity, verified.ParentIdentity, StringComparison.OrdinalIgnoreCase);
    }

    internal async Task<VerifiedBrokerFileTarget> VerifyLockedAsync(RemediationAction action,
        SecureFileLease lease, BrokerDirectoryLease parent, CancellationToken token)
    {
        if (Volatile.Read(ref _state) != 2 || !Contains(action, lease.FinalPath, action.ExpectedSha256) ||
            !_targets.TryGetValue(action.ActionId, out VerifiedBrokerFileTarget? target))
            throw BrokerScopeText.Denied(BrokerScopeText.NotAuthorized);
        if (!parent.ParentIdentity.Equals(target.ParentIdentity, StringComparison.OrdinalIgnoreCase))
            throw BrokerScopeText.Denied(BrokerScopeText.IdentityChanged);
        _ = RequireIdentity(lease, target.FileIdentity);
        if (!(await lease.ComputeSha256Async(token)).Equals(target.Sha256, StringComparison.OrdinalIgnoreCase))
            throw BrokerScopeText.Invalid(BrokerScopeText.IdentityChanged);
        if (target.Metadata is not null && BrokerFileMetadata.Capture(lease.Handle, lease.FinalPath, lease.HasSecurityAccess) != target.Metadata)
            throw BrokerScopeText.Denied(BrokerScopeText.IdentityChanged);
        return target;
    }

    internal static void RequireSafePath(string path)
    {
        FileScopeSafetyResult safety = FileScopeSafety.EvaluatePath(path);
        if (!safety.Allowed)
            throw MessageExceptions.Create(safety.Message, text => new UnauthorizedAccessException(text));
    }

    private static string RequireIdentity(SecureFileLease lease, string expected)
    {
        RequireSafePath(lease.FinalPath);
        FileScopeSafety.ValidateHandlePath(lease.Handle, lease.FinalPath);
        if (FileScopeSafety.ReadLinkCount(lease.Handle) != 1)
            throw BrokerScopeText.Denied(BrokerScopeText.HardLinks);
        string actual = FileScopeSafety.ReadIdentity(lease.Handle);
        if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
            throw BrokerScopeText.Denied(BrokerScopeText.IdentityChanged);
        return actual;
    }

    private static bool IsFileAction(RemediationAction action) =>
        action.Type is RemediationActionType.QuarantineFile or RemediationActionType.AddProgramFirewallBlock;

    private static bool SamePath(string left, string right)
    {
        try { return Path.GetFullPath(left).Equals(Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return false; }
    }
}

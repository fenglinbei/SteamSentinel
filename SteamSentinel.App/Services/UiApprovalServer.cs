using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.App.Services;

/// <summary>单次消费、仅当前会话与管理员可连入的 UI 已确认计划批准服务端。</summary>
internal sealed class UiApprovalServer : IAsyncDisposable
{
    private readonly Guid _planId;
    private readonly string _planIdentitySha256;
    private readonly NamedPipeServerStream _server;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Task _listenTask;

    public string PipeName { get; }

    internal UiApprovalServer(Guid planId, string planIdentitySha256)
    {
        if (planId == Guid.Empty) throw new ArgumentException("PlanId must not be empty.", nameof(planId));
        if (!Validation.IsHexSha256(planIdentitySha256)) throw new ArgumentException("Invalid PlanIdentitySha256.", nameof(planIdentitySha256));

        _planId = planId;
        _planIdentitySha256 = planIdentitySha256.ToUpperInvariant();
        PipeName = UiApprovalProtocol.CreatePipeName();
        _server = NamedPipeServerStreamAcl.Create(
            PipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: UiApprovalProtocol.MaximumMessageBytes,
            outBufferSize: UiApprovalProtocol.MaximumMessageBytes,
            BuildPipeSecurity());
        _listenTask = ListenOnceAsync(_lifetime.Token);
    }

    private static PipeSecurity BuildPipeSecurity()
    {
        PipeSecurity security = new();
        using WindowsIdentity current = WindowsIdentity.GetCurrent();
        if (current.User is not null)
        {
            security.AddAccessRule(new PipeAccessRule(current.User, PipeAccessRights.FullControl, AccessControlType.Allow));
        }
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.NetworkSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Deny));
        return security;
    }

    private async Task ListenOnceAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
            using CancellationTokenSource handshakeTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeTimeout.CancelAfter(UiApprovalProtocol.HandshakeTimeout);

            UiApprovalChallenge? challenge = await UiApprovalProtocol.ReadMessageAsync<UiApprovalChallenge>(_server, handshakeTimeout.Token).ConfigureAwait(false);
            if (challenge is not null &&
                challenge.PlanId == _planId &&
                string.Equals(challenge.PlanIdentitySha256, _planIdentitySha256, StringComparison.OrdinalIgnoreCase) &&
                Validation.IsHexSha256(challenge.BrokerNonce))
            {
                string ackDigest = UiApprovalProtocol.ComputeAckDigest(_planId, _planIdentitySha256, challenge.BrokerNonce);
                UiApprovalResponse response = new(_planId, _planIdentitySha256, challenge.BrokerNonce, ackDigest);
                await UiApprovalProtocol.WriteMessageAsync(_server, response, handshakeTimeout.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception) { }
        finally
        {
            try
            {
                if (_server.IsConnected) _server.Disconnect();
            }
            catch { }
            try { _server.Dispose(); } catch { }
        }
    }

    public async ValueTask DisposeAsync()
    {
        try { _lifetime.Cancel(); } catch { }
        try { _server.Dispose(); } catch { }
        try { await _listenTask.ConfigureAwait(false); } catch { }
        _lifetime.Dispose();
    }
}

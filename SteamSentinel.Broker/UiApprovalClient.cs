using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Broker;

/// <summary>通过内核验证管道服务端身份、会话、用户 SID 与一次性 Challenge-Response 核验 UI 预先确认状态。</summary>
internal static class UiApprovalClient
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;
    private const int TokenUserClass = 1;

    internal static async Task<bool> TryVerifyApprovalAsync(
        string? pipeName,
        RemediationPlan plan,
        string planIdentitySha256,
        CancellationToken cancellationToken = default,
        Func<int, string?, bool>? isAllowedServerForTest = null)
    {
        if (!UiApprovalProtocol.IsValidPipeName(pipeName) ||
            plan is null ||
            plan.PlanId == Guid.Empty ||
            string.IsNullOrWhiteSpace(plan.RequestedBySid) ||
            !Validation.IsHexSha256(planIdentitySha256))
        {
            return false;
        }

        // 回滚与永久删除事件必须始终经过管理员确认弹窗，绝不通过 UI 管道跳过。
        if (plan.Actions.Any(action => action.Type is RemediationActionType.RollbackIncident or RemediationActionType.DeleteIncident))
        {
            return false;
        }

        try
        {
            using CancellationTokenSource handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(UiApprovalProtocol.HandshakeTimeout);

            using NamedPipeClientStream client = new(".", pipeName!, PipeDirection.InOut, PipeOptions.Asynchronous);
            await client.ConnectAsync(3000, handshakeCts.Token).ConfigureAwait(false);

            if (!VerifyServerIdentity(client.SafePipeHandle, plan.RequestedBySid, isAllowedServerForTest))
            {
                return false;
            }

            string brokerNonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            UiApprovalChallenge challenge = new(plan.PlanId, planIdentitySha256.ToUpperInvariant(), brokerNonce);
            await UiApprovalProtocol.WriteMessageAsync(client, challenge, handshakeCts.Token).ConfigureAwait(false);

            UiApprovalResponse? response = await UiApprovalProtocol.ReadMessageAsync<UiApprovalResponse>(client, handshakeCts.Token).ConfigureAwait(false);
            if (response is null ||
                response.PlanId != plan.PlanId ||
                !string.Equals(response.PlanIdentitySha256, planIdentitySha256, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(response.BrokerNonce, brokerNonce, StringComparison.OrdinalIgnoreCase) ||
                !Validation.IsHexSha256(response.AckDigestSha256))
            {
                return false;
            }

            string expectedAck = UiApprovalProtocol.ComputeAckDigest(plan.PlanId, planIdentitySha256, brokerNonce);
            return CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(expectedAck),
                Encoding.ASCII.GetBytes(response.AckDigestSha256.ToUpperInvariant()));
        }
        catch
        {
            return false;
        }
    }

    private static bool VerifyServerIdentity(
        SafePipeHandle pipeHandle,
        string expectedUserSid,
        Func<int, string?, bool>? isAllowedServerForTest)
    {
        if (!GetNamedPipeServerProcessId(pipeHandle, out uint serverPid) || serverPid == 0)
            return false;

        if (!ProcessIdToSessionId(serverPid, out uint serverSession) ||
            !ProcessIdToSessionId((uint)Environment.ProcessId, out uint currentSession) ||
            serverSession != currentSession)
        {
            return false;
        }

        using SafeProcessHandle process = OpenProcess(ProcessQueryLimitedInformation, false, serverPid);
        if (process.IsInvalid) return false;

        string? serverUserSid = TryReadProcessUserSid(process);
        if (string.IsNullOrWhiteSpace(serverUserSid) ||
            !serverUserSid.Equals(expectedUserSid, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string? imagePath = TryReadProcessImagePath(process);
        if (isAllowedServerForTest is not null)
        {
            return isAllowedServerForTest((int)serverPid, imagePath);
        }

        if (string.IsNullOrWhiteSpace(imagePath) || Validation.ContainsReparsePoint(imagePath))
            return false;

        string baseDir = Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory));
        string? serverDir = Path.GetDirectoryName(Path.GetFullPath(imagePath));
        if (serverDir is null ||
            !Path.TrimEndingDirectorySeparator(serverDir).Equals(baseDir, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return StartupCompatibility.TryIdentifyHost(imagePath, StartupRole.App, out _, out _);
    }

    private static string? TryReadProcessUserSid(SafeProcessHandle process)
    {
        if (!OpenProcessToken(process, TokenQuery, out SafeAccessTokenHandle token))
            return null;

        using (token)
        {
            _ = GetTokenInformation(token, TokenUserClass, IntPtr.Zero, 0, out uint needed);
            if (needed == 0 || needed > 4096) return null;

            IntPtr buffer = Marshal.AllocHGlobal((int)needed);
            try
            {
                if (!GetTokenInformation(token, TokenUserClass, buffer, needed, out _))
                    return null;
                IntPtr sidPtr = Marshal.ReadIntPtr(buffer);
                return sidPtr == IntPtr.Zero ? null : new SecurityIdentifier(sidPtr).Value;
            }
            catch
            {
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    private static string? TryReadProcessImagePath(SafeProcessHandle process)
    {
        char[] buffer = new char[1024];
        uint size = (uint)buffer.Length;
        if (!QueryFullProcessImageNameW(process, 0, buffer, ref size) || size == 0)
            return null;
        return new string(buffer, 0, (int)size);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle Pipe, out uint ServerProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(SafeProcessHandle ProcessHandle, uint DesiredAccess, out SafeAccessTokenHandle TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(SafeProcessHandle hProcess, uint dwFlags, [Out] char[] lpExeName, ref uint lpdwSize);
}

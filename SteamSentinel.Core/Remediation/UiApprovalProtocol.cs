using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Remediation;

public sealed record UiApprovalChallenge(Guid PlanId, string PlanIdentitySha256, string BrokerNonce);

public sealed record UiApprovalResponse(Guid PlanId, string PlanIdentitySha256, string BrokerNonce, string AckDigestSha256);

/// <summary>UI 确认后通过受限一次性 Named Pipe 向提权 Broker 传递内核可验证批准的握手协议。</summary>
public static class UiApprovalProtocol
{
    public const string ApprovalPipeArgument = "--ui-approval-pipe";
    public const string PipeNamePrefix = "SteamSentinel.UiApproval.";
    public const int MaximumMessageBytes = 4096;
    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(5);

    public static string CreatePipeName() => PipeNamePrefix + Guid.NewGuid().ToString("N");

    public static bool IsValidPipeName(string? pipeName)
    {
        if (string.IsNullOrEmpty(pipeName) ||
            pipeName.Length != PipeNamePrefix.Length + 32 ||
            !pipeName.StartsWith(PipeNamePrefix, StringComparison.Ordinal))
        {
            return false;
        }

        ReadOnlySpan<char> suffix = pipeName.AsSpan(PipeNamePrefix.Length);
        foreach (char c in suffix)
        {
            bool hex = c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');
            if (!hex) return false;
        }
        return true;
    }

    public static string ComputeAckDigest(Guid planId, string planIdentitySha256, string brokerNonce)
    {
        string payload = $"SteamSentinel.UiApproval.v1\n{planId:N}\n{planIdentitySha256.ToUpperInvariant()}\n{brokerNonce.ToUpperInvariant()}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
    }

    public static async Task WriteMessageAsync<T>(Stream stream, T payload, CancellationToken cancellationToken = default)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(payload, JsonFile.Options);
        if (json.Length is <= 0 or > MaximumMessageBytes)
            throw new InvalidDataException("UI approval handshake message exceeds protocol bounds.");

        byte[] lengthPrefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(lengthPrefix, json.Length);
        await stream.WriteAsync(lengthPrefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(json, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<T?> ReadMessageAsync<T>(Stream stream, CancellationToken cancellationToken = default)
    {
        byte[] lengthPrefix = new byte[4];
        if (!await ReadExactOrEofAsync(stream, lengthPrefix, cancellationToken).ConfigureAwait(false))
            return default;

        int length = BinaryPrimitives.ReadInt32LittleEndian(lengthPrefix);
        if (length is <= 0 or > MaximumMessageBytes)
            return default;

        byte[] buffer = new byte[length];
        if (!await ReadExactOrEofAsync(stream, buffer, cancellationToken).ConfigureAwait(false))
            return default;

        try { return JsonSerializer.Deserialize<T>(buffer, JsonFile.Options); }
        catch (JsonException) { return default; }
    }

    private static async Task<bool> ReadExactOrEofAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }
}

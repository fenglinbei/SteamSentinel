using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using SteamSentinel.Core.Models;

namespace SteamSentinel.App.Services;

internal enum WorkerStage { Preflight, RestrictedStart, Handshake, Scanning, Exit }

internal sealed class WorkerFailureException : Exception
{
    public WorkerStage Stage { get; }
    public int? NativeExitCode { get; }
    public string ReasonCode { get; }
    public ScanReport? PartialReport { get; init; }
    public bool BeforeScan => Stage is WorkerStage.Preflight or WorkerStage.RestrictedStart or WorkerStage.Handshake;

    internal WorkerFailureException(WorkerStage stage, int? exitCode, MessageText detail, Exception? inner = null, string? reasonCode = null)
        : base(Describe(stage, exitCode, detail, inner, ResolveReason(stage, inner, reasonCode)).OriginalText, inner)
    {
        Stage = stage;
        NativeExitCode = exitCode;
        ReasonCode = ResolveReason(stage, inner, reasonCode);
        MessageExceptions.Attach(this, Describe(stage, exitCode, detail, inner, ReasonCode));
    }

    private static string ResolveReason(WorkerStage stage, Exception? inner, string? reason) =>
        ReasonCodes.IsValid(reason) ? reason! : stage is WorkerStage.Preflight or WorkerStage.RestrictedStart or WorkerStage.Handshake
            ? ReasonCodes.WorkerStartFailed : ReasonCodes.ForFailureType(inner?.GetType().Name);

    private static MessageText Describe(WorkerStage stage, int? code, MessageText detail, Exception? inner, string reasonCode)
    {
        MessageText phase = stage switch
        {
            WorkerStage.Preflight => MessageText.Create("WorkerFailureException.Describe.Preflight.01"),
            WorkerStage.RestrictedStart => MessageText.Create("WorkerFailureException.Describe.RestrictedStart.01"),
            WorkerStage.Handshake => MessageText.Create("WorkerFailureException.Describe.Handshake.01"),
            WorkerStage.Scanning => MessageText.Create("WorkerFailureException.Describe.Scanning.01"),
            _ => MessageText.Create("WorkerFailureException.Describe.01")
        };
        MessageText reason = code is int value
            ? MessageText.Create("WorkerFailureException.Describe.02", unchecked((uint)value).ToString("X8", System.Globalization.CultureInfo.InvariantCulture)) : MessageText.Create("WorkerFailureException.Describe.03");
        if (inner is Win32Exception win32) reason += MessageText.Create("WorkerFailureException.Describe.04", (win32.NativeErrorCode));
        MessageText advice = reasonCode == ReasonCodes.ResourceLimit
            ? MessageText.Create("WorkerFailureException.Describe.05")
            : reasonCode == ReasonCodes.AllocationFailed
            ? MessageText.Create("WorkerFailureException.Describe.06")
            : code == unchecked((int)0xC0000142)
            ? MessageText.Create("WorkerFailureException.Describe.07")
            : stage == WorkerStage.Preflight
                ? MessageText.Create("WorkerFailureException.Describe.08")
                : MessageText.Create("WorkerFailureException.Describe.09");
        return MessageText.Create("WorkerFailureException.Describe.10", ((stage is WorkerStage.Preflight or WorkerStage.RestrictedStart or WorkerStage.Handshake ? MessageText.Create("WorkerFailureException.Describe.11") : MessageText.Create("WorkerFailureException.Describe.12"))), (phase), (reason), (Limit(detail)), (advice));
    }

    internal static string Limit(string text)
    {
        string clean = string.Concat(text.Where(c => !char.IsControl(c) || c is '\n' or '\r' or '\t'));
        return clean.Length <= 2048 ? clean.Trim() : clean[..2048].Trim() + MessageText.Create("WorkerFailureException.Limit.01");
    }

    internal static MessageText Limit(MessageText text)
    {
        string limited = Limit(text.OriginalText);
        return limited == text.OriginalText ? text : new(limited);
    }
}

internal sealed class WorkerCancelledException : OperationCanceledException
{
    internal WorkerCancelledException(ScanReport? partialReport, CancellationToken token)
        : base(MessageText.Create("WorkerFailureException.Text.01").OriginalText, token)
    {
        PartialReport = partialReport;
        MessageExceptions.Attach(this, MessageText.Create("WorkerFailureException.Text.01"));
    }
    public ScanReport? PartialReport { get; }
}

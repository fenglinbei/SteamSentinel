using System.Globalization;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Reporting;

/// <summary>Render recorded engine facts; never interpret HRESULT text or a raw result as a verdict.</summary>
public static class AmsiPresentation
{
    public static string Describe(AmsiDiagnosticInfo diagnostic, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        string key = diagnostic.Code switch
        {
            "AMSI-READY" => "Amsi.Ready",
            "AMSI-INITIALIZE-FAILED" => "Amsi.InitializeFailed",
            "AMSI-INVALID-CONTEXT" => "Amsi.InvalidContext",
            "AMSI-SESSION-UNAVAILABLE" => "Amsi.SessionUnavailable",
            "AMSI-LIBRARY-NOT-FOUND" => "Amsi.LibraryMissing",
            "AMSI-ENTRYPOINT-NOT-FOUND" => "Amsi.EntryMissing",
            "AMSI-LIBRARY-FORMAT" => "Amsi.LibraryFormat",
            "AMSI-DISPOSED" => "Amsi.Disposed",
            "AMSI-EMPTY" => "Amsi.Empty",
            "AMSI-SCAN-FAILED" => "Amsi.ScanFailed",
            "AMSI-VERDICT" => "Amsi.VerdictReturned",
            "AMSI-SIZE-LIMIT" => "Amsi.SizeLimit",
            _ => "Amsi.Unknown"
        };
        return DisplayText.Get(key) + Environment.NewLine + DisplayText.Format("Amsi.Diagnostic",
            diagnostic.Operation, diagnostic.Code, HResult(diagnostic.HResult), HResult(diagnostic.InitializeHResult),
            HResult(diagnostic.OpenSessionHResult), diagnostic.Architecture, diagnostic.Integrity);
    }

    public static string Describe(AmsiScanResult result, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        string detail = result.Diagnostics is { } diagnostic ? Describe(diagnostic) : DisplayText.Get("Amsi.Unknown");
        // Empty input, failed calls and legacy records do not establish a successful engine scan.
        if (result.Diagnostics is { Code: "AMSI-VERDICT", Operation: AmsiOperation.ScanBuffer, HResult: >= 0 } && result.BytesSubmitted > 0)
            detail += Environment.NewLine + DisplayText.Format("Amsi.Result", VerdictLabel(result.Verdict), result.RawResult, result.BytesSubmitted);
        if (!string.IsNullOrEmpty(result.Detail)) detail += Environment.NewLine + DisplayText.Format("Common.RawDetail", result.Detail);
        return detail;
    }

    public static string VerdictLabel(AmsiVerdict verdict, CultureInfo? culture = null)
    {
        using IDisposable scope = DisplayText.UseCulture(culture);
        return DisplayText.Get(Enum.IsDefined(verdict) ? "Amsi.Verdict." + verdict : "Common.Unknown");
    }

    private static string HResult(int? value) => value is int code ? "0x" + code.ToString("X8", CultureInfo.InvariantCulture) : DisplayText.Get("Common.NotRecorded");
}

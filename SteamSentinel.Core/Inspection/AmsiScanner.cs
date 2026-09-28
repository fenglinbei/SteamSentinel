using SteamSentinel.Core.Reporting;
using System.Runtime.InteropServices;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.Core.Inspection;

public enum AmsiVerdict
{
    Unavailable,
    Clean,
    NotDetected,
    BlockedByPolicy,
    Detected,
    Error
}
[method: System.Text.Json.Serialization.JsonConstructor]
public sealed record AmsiScanResult(AmsiVerdict Verdict, int RawResult, string Detail)
{
    public AmsiDiagnosticInfo? Diagnostics { get; init; }
    public long BytesSubmitted { get; init; }
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public AmsiScanResult(AmsiVerdict Verdict, int RawResult, SteamSentinel.Core.Reporting.MessageText Detail) : this(Verdict, RawResult, Detail.OriginalText)
    {
        DetailMessage = Detail.Message;
    }
}

internal interface IAmsiApi
{
    int Initialize(string name, out IntPtr context);
    int OpenSession(IntPtr context, out IntPtr session);
    int ScanBuffer(IntPtr context, byte[] buffer, string name, IntPtr session, out int result);
    void CloseSession(IntPtr context, IntPtr session);
    void Uninitialize(IntPtr context);
}

public sealed class AmsiScanner : IDisposable
{
    private const int AmsiResultDetected = 32768;
    private IntPtr _context;
    private IntPtr _session;
    private bool _disposed;
    private readonly IAmsiApi _api;
    private readonly string _integrity = ReadIntegrity();
    private int? _initializeHResult, _openSessionHResult;
    private int? _startupHResult;
    private AmsiOperation _startupOperation = AmsiOperation.Initialize;
    private string _initializationCode = "AMSI-READY";
    public AmsiDiagnosticInfo Initialization => Diagnostic(_startupOperation, _initializationCode, _startupHResult);

    public AmsiScanner() : this(new WindowsAmsiApi()) { }

    internal AmsiScanner(IAmsiApi api)
    {
        _api = api;
        try
        {
            _initializeHResult = _api.Initialize(ProductInfo.Name, out _context);
            _startupHResult = _initializeHResult;
            if (_initializeHResult < 0 || _context == IntPtr.Zero)
            {
                _context = IntPtr.Zero;
                _initializationCode = _initializeHResult < 0 ? "AMSI-INITIALIZE-FAILED" : "AMSI-INVALID-CONTEXT";
                return;
            }
            _startupOperation = AmsiOperation.OpenSession;
            _openSessionHResult = _api.OpenSession(_context, out _session);
            _startupHResult = _openSessionHResult;
            // A null session is supported by AmsiScanBuffer. Preserve the failure,
            // but do not suppress an engine verdict just because correlation is unavailable.
            if (_openSessionHResult < 0) { _session = IntPtr.Zero; _initializationCode = "AMSI-SESSION-UNAVAILABLE"; }
        }
        catch (Exception exception) when (exception is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            _initializationCode = exception switch
            {
                DllNotFoundException => "AMSI-LIBRARY-NOT-FOUND",
                EntryPointNotFoundException => "AMSI-ENTRYPOINT-NOT-FOUND",
                _ => "AMSI-LIBRARY-FORMAT"
            };
            _startupHResult = exception.HResult;
            if (_startupOperation == AmsiOperation.Initialize) _initializeHResult = exception.HResult;
            else
            {
                _openSessionHResult = exception.HResult;
                if (_context != IntPtr.Zero) _api.Uninitialize(_context);
            }
            _context = IntPtr.Zero;
        }
    }

    private AmsiDiagnosticInfo Diagnostic(AmsiOperation operation, string code, int? hresult) =>
        new(code, operation, hresult, _initializeHResult, _openSessionHResult,
            RuntimeInformation.ProcessArchitecture.ToString(), _integrity);

    private static string ReadIntegrity()
    {
        try { return ProcessIntegrity.GetCurrent().ToString(); }
        catch (System.ComponentModel.Win32Exception) { return nameof(ProcessIntegrityLevel.Unknown); }
    }

    private AmsiScanResult Result(AmsiVerdict verdict, int raw, MessageText detail, string code,
        AmsiOperation operation, int? hresult = null, long submitted = 0) => new(verdict, raw, detail)
        { Diagnostics = Diagnostic(operation, code, hresult), BytesSubmitted = submitted };

    private AmsiScanResult Unavailable() => _disposed
        ? Result(AmsiVerdict.Unavailable, 0, MessageText.Create("AmsiScanner.Unavailable.01"), "AMSI-DISPOSED", AmsiOperation.Disposed)
        : Result(AmsiVerdict.Unavailable, 0,
            MessageText.Create("Amsi.Unavailable", _startupOperation, _initializationCode,
                _startupHResult is int hr ? (MessageText)$"0x{hr:X8}" : MessageText.Create("Common.NotRecorded")),
            _initializationCode, _startupOperation, _startupHResult);

    public AmsiScanResult Scan(ReadOnlySpan<byte> content, string contentName)
    {
        if (_disposed || _context == IntPtr.Zero)
        {
            return Unavailable();
        }

        if (content.Length == 0)
        {
            return Result(AmsiVerdict.Clean, 0, MessageText.Create("AmsiScanner.Scan.01"), "AMSI-EMPTY", AmsiOperation.Input);
        }

        byte[] bytes = content.ToArray();
        try
        {
            return ScanOwnedBuffer(bytes, contentName);
        }
        finally { Array.Clear(bytes); }
    }

    private AmsiScanResult ScanOwnedBuffer(byte[] bytes, string contentName)
    {
        int hr = _api.ScanBuffer(_context, bytes, contentName, _session, out int result);
        if (hr < 0)
        {
            return Result(AmsiVerdict.Error, result, MessageText.Create("AmsiScanner.ScanOwnedBuffer.01", System.FormattableString.Invariant($"{hr:X8}")),
                "AMSI-SCAN-FAILED", AmsiOperation.ScanBuffer, hr, bytes.Length);
        }

        AmsiVerdict verdict = result switch
        {
            >= AmsiResultDetected => AmsiVerdict.Detected,
            >= 0x4000 => AmsiVerdict.BlockedByPolicy,
            0 => AmsiVerdict.Clean,
            _ => AmsiVerdict.NotDetected
        };
        return Result(verdict, result, MessageText.Create("AmsiScanner.ScanOwnedBuffer.02", (result)), "AMSI-VERDICT", AmsiOperation.ScanBuffer, hr, bytes.Length);
    }

    public async Task<AmsiScanResult> ScanFileAsync(
        string path,
        long maximumBytes = 32L * 1024 * 1024,
        CancellationToken cancellationToken = default)
    {
        if (_disposed || _context == IntPtr.Zero) return Unavailable();
        await using FileStream input = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.Asynchronous);
        return await ScanStreamAsync(input, path, maximumBytes, cancellationToken);
    }

    public async Task<AmsiScanResult> ScanStreamAsync(Stream input, string contentName,
        long maximumBytes = 32L * 1024 * 1024, CancellationToken cancellationToken = default)
    {
        if (_disposed || _context == IntPtr.Zero) return Unavailable();
        input.Position = 0;
        long length = input.Length;
        if (length > Math.Min(maximumBytes, Array.MaxLength))
        {
            return Result(AmsiVerdict.Error, 1, MessageText.Create("AmsiScanner.ScanStreamAsync.01", (maximumBytes)),
                "AMSI-SIZE-LIMIT", AmsiOperation.Input);
        }
        if (length == 0) return Result(AmsiVerdict.Clean, 0, MessageText.Create("AmsiScanner.ScanStreamAsync.02"), "AMSI-EMPTY", AmsiOperation.Input);
        byte[] bytes = new byte[(int)length];
        try
        {
            await input.ReadExactlyAsync(bytes, cancellationToken);
            if (input.ReadByte() != -1) throw SteamSentinel.Core.Reporting.MessageExceptions.Create(MessageText.Create("AmsiScanner.ScanStreamAsync.03"), sourceText => new InvalidDataException(sourceText));
            return ScanOwnedBuffer(bytes, contentName);
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        if (_context != IntPtr.Zero)
        {
            if (_session != IntPtr.Zero) _api.CloseSession(_context, _session);
            _api.Uninitialize(_context);
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private sealed class WindowsAmsiApi : IAmsiApi
    {
        public int Initialize(string name, out IntPtr context) => AmsiInitialize(name, out context);
        public int OpenSession(IntPtr context, out IntPtr session) => AmsiOpenSession(context, out session);
        public int ScanBuffer(IntPtr context, byte[] buffer, string name, IntPtr session, out int result) =>
            AmsiScanBuffer(context, buffer, (uint)buffer.Length, name, session, out result);
        public void CloseSession(IntPtr context, IntPtr session) => AmsiCloseSession(context, session);
        public void Uninitialize(IntPtr context) => AmsiUninitialize(context);
    }

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiInitialize(string appName, out IntPtr context);

    [DllImport("amsi.dll")]
    private static extern int AmsiOpenSession(IntPtr context, out IntPtr session);

    [DllImport("amsi.dll")]
    private static extern void AmsiCloseSession(IntPtr context, IntPtr session);

    [DllImport("amsi.dll")]
    private static extern void AmsiUninitialize(IntPtr context);

    [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
    private static extern int AmsiScanBuffer(
        IntPtr context,
        byte[] buffer,
        uint length,
        string contentName,
        IntPtr session,
        out int result);
}

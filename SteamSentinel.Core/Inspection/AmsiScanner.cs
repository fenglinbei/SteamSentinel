using System.Runtime.InteropServices;
using SteamSentinel.Core.Models;

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

public sealed record AmsiScanResult(AmsiVerdict Verdict, int RawResult, string Detail);

public sealed class AmsiScanner : IDisposable
{
    private const int AmsiResultDetected = 32768;
    private IntPtr _context;
    private IntPtr _session;
    private bool _disposed;

    public AmsiScanner()
    {
        try
        {
            int hr = AmsiInitialize(ProductInfo.Name, out _context);
            if (hr >= 0 && _context != IntPtr.Zero)
            {
                _ = AmsiOpenSession(_context, out _session);
            }
        }
        catch (DllNotFoundException)
        {
            _context = IntPtr.Zero;
        }
    }

    public AmsiScanResult Scan(ReadOnlySpan<byte> content, string contentName)
    {
        if (_disposed || _context == IntPtr.Zero)
        {
            return new AmsiScanResult(AmsiVerdict.Unavailable, 0, "AMSI 不可用。");
        }

        if (content.Length == 0)
        {
            return new AmsiScanResult(AmsiVerdict.Clean, 0, "空内容。");
        }

        byte[] bytes = content.ToArray();
        try
        {
            int hr = AmsiScanBuffer(_context, bytes, (uint)bytes.Length, contentName, _session, out int result);
            if (hr < 0)
            {
                return new AmsiScanResult(AmsiVerdict.Error, result, $"AMSI 调用失败：0x{hr:X8}");
            }

            AmsiVerdict verdict = result switch
            {
                >= AmsiResultDetected => AmsiVerdict.Detected,
                >= 0x4000 => AmsiVerdict.BlockedByPolicy,
                0 => AmsiVerdict.Clean,
                _ => AmsiVerdict.NotDetected
            };
            return new AmsiScanResult(verdict, result, $"AMSI 返回值：{result}");
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    public async Task<AmsiScanResult> ScanFileAsync(
        string path,
        long maximumBytes = 32L * 1024 * 1024,
        CancellationToken cancellationToken = default)
    {
        FileInfo info = new(path);
        if (info.Length > maximumBytes)
        {
            return new AmsiScanResult(AmsiVerdict.NotDetected, 1, $"文件超过 AMSI 内存扫描上限 {maximumBytes} 字节。");
        }

        byte[] bytes = await File.ReadAllBytesAsync(path, cancellationToken);
        try
        {
            return Scan(bytes, path);
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
            if (_session != IntPtr.Zero) AmsiCloseSession(_context, _session);
            AmsiUninitialize(_context);
        }

        _disposed = true;
        GC.SuppressFinalize(this);
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

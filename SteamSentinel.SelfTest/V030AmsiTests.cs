using System.Globalization;
using System.IO;
using System.Text.Json;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV030AmsiDiagnosticsAsync(string root)
    {
        const int denied = unchecked((int)0x80070005), failure = unchecked((int)0x80004005);
        byte[] inert = "SteamSentinel harmless AMSI diagnostic fixture."u8.ToArray();
        V030AmsiApi unavailable = new() { InitializeResult = denied };
        using (AmsiScanner scanner = new(unavailable))
        {
            AmsiScanResult result = scanner.Scan(inert, "inert");
            Check("0.3 AMSI 初始化失败保留真实 HRESULT 与阶段", result.Verdict == AmsiVerdict.Unavailable &&
                result.Diagnostics is { Code: "AMSI-INITIALIZE-FAILED", Operation: AmsiOperation.Initialize, HResult: denied, InitializeHResult: denied });
            Check("0.3 AMSI 未提交内容不宣称引擎读取", result.BytesSubmitted == 0 && unavailable.ScanCalls == 0 && unavailable.SessionCalls == 0);
            Check("0.3 AMSI 不可用时空输入也不伪装提供程序成功", scanner.Scan([], "empty").Verdict == AmsiVerdict.Unavailable);
        }
        using (AmsiScanner scanner = new(new V030AmsiApi { Context = IntPtr.Zero }))
            Check("0.3 AMSI S_OK 但空上下文与明确初始化错误分开", scanner.Scan(inert, "inert").Diagnostics is
            { Code: "AMSI-INVALID-CONTEXT", HResult: 0 });

        V030AmsiApi noSession = new() { SessionResult = denied };
        AmsiScanner sessionScanner = new(noSession);
        AmsiScanResult withoutSession = sessionScanner.Scan(inert, "inert");
        Check("0.3 AMSI 会话失败仍记录且允许官方支持的空会话扫描", withoutSession.Verdict == AmsiVerdict.NotDetected &&
            withoutSession.Diagnostics is { InitializeHResult: 0, OpenSessionHResult: denied, HResult: 0, Operation: AmsiOperation.ScanBuffer } &&
            noSession.LastSession == IntPtr.Zero && sessionScanner.Initialization.Operation == AmsiOperation.OpenSession);
        sessionScanner.Dispose(); sessionScanner.Dispose();
        Check("0.3 AMSI 只释放有效上下文且 Dispose 幂等", noSession.CloseCalls == 0 && noSession.UninitializeCalls == 1 &&
            sessionScanner.Scan(inert, "inert").Diagnostics?.Code == "AMSI-DISPOSED");

        V030AmsiApi scanFailure = new() { ScanResult = failure, Verdict = 32768 };
        using (AmsiScanner scanner = new(scanFailure))
        {
            AmsiScanResult result = scanner.Scan(inert, "inert");
            Check("0.3 AMSI 调用失败不能被原始结果值转成威胁判定", result.Verdict == AmsiVerdict.Error &&
                result.Diagnostics is { Code: "AMSI-SCAN-FAILED", HResult: failure } && result.BytesSubmitted == inert.Length);
        }
        foreach (var item in new[] { (0, AmsiVerdict.Clean), (1, AmsiVerdict.NotDetected), (0x3fff, AmsiVerdict.NotDetected),
                     (0x4000, AmsiVerdict.BlockedByPolicy), (0x7fff, AmsiVerdict.BlockedByPolicy), (0x8000, AmsiVerdict.Detected) })
        {
            V030AmsiApi api = new() { Verdict = item.Item1 };
            using AmsiScanner scanner = new(api);
            AmsiScanResult result = scanner.Scan(inert, "inert");
            Check($"0.3 AMSI 结果边界 {item.Item1} 与诊断不混用", result.Verdict == item.Item2 && result.RawResult == item.Item1 &&
                result.Diagnostics?.HResult == 0 && result.BytesSubmitted == inert.Length);
            Check("0.3 AMSI 提交缓冲在使用后清除且不改输入", api.LastBuffer is not null && api.LastBuffer.All(b => b == 0) && inert[0] == (byte)'S');
        }

        V030AmsiApi bounded = new();
        using (AmsiScanner scanner = new(bounded))
        {
            using MemoryStream input = new(inert);
            AmsiScanResult result = await scanner.ScanStreamAsync(input, "inert", inert.Length - 1);
            Check("0.3 AMSI 大小限制在提交前执行并保留独立原因", bounded.ScanCalls == 0 && result.BytesSubmitted == 0 && result.Diagnostics is
            { Code: "AMSI-SIZE-LIMIT", Operation: AmsiOperation.Input, HResult: null });
            using CancellationTokenSource cancel = new(); cancel.Cancel();
            bool cancelled = false;
            try { await scanner.ScanStreamAsync(input, "inert", cancellationToken: cancel.Token); }
            catch (OperationCanceledException) { cancelled = true; }
            Check("0.3 AMSI 读取取消不继续提交", cancelled && bounded.ScanCalls == 0);
        }
        using (AmsiScanner scanner = new(new V030AmsiApi { MissingLibrary = true }))
            Check("0.3 AMSI 缺失库保留受控诊断", scanner.Scan(inert, "inert").Diagnostics is
            { Code: "AMSI-LIBRARY-NOT-FOUND", Operation: AmsiOperation.Initialize, HResult: not null });
        V030AmsiApi missingSession = new() { MissingSessionEntryPoint = true };
        using (AmsiScanner scanner = new(missingSession))
            Check("0.3 AMSI 会话入口异常保留正确阶段并释放初始化资源", scanner.Scan(inert, "inert").Diagnostics is
            { Code: "AMSI-ENTRYPOINT-NOT-FOUND", Operation: AmsiOperation.OpenSession, InitializeHResult: 0, OpenSessionHResult: not null } &&
                missingSession.UninitializeCalls == 1);

        CultureInfo before = CultureInfo.CurrentUICulture;
        AmsiDiagnosticInfo? zh = null, en = null;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("zh-CN");
            using (AmsiScanner scanner = new(new V030AmsiApi { InitializeResult = denied })) zh = scanner.Scan(inert, "inert").Diagnostics;
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");
            using (AmsiScanner scanner = new(new V030AmsiApi { InitializeResult = denied })) en = scanner.Scan(inert, "inert").Diagnostics;
        }
        finally { CultureInfo.CurrentUICulture = before; }
        Check("0.3 AMSI 结构化诊断不随界面语言变化", zh == en);
        ContainerEngineObservation observation = new() { Engine = "AMSI", Status = ContainerStageStatus.Failed, Length = 0, AmsiDiagnostics = zh };
        string json = JsonSerializer.Serialize(observation, JsonFile.Options);
        Check("0.3 AMSI JSON 往返保留代码架构权限与 HRESULT", JsonSerializer.Deserialize<ContainerEngineObservation>(json, JsonFile.Options)?.AmsiDiagnostics == zh &&
            zh is { Architecture.Length: > 0, Integrity.Length: > 0 });
        await File.WriteAllTextAsync(Path.Combine(root, "v030-amsi-diagnostic-fixture.json"), json);
    }

    private sealed class V030AmsiApi : IAmsiApi
    {
        internal int InitializeResult, SessionResult, ScanResult;
        internal int Verdict = 1;
        internal IntPtr Context = new(1);
        internal bool MissingLibrary, MissingSessionEntryPoint;
        internal int ScanCalls, SessionCalls, CloseCalls, UninitializeCalls;
        internal IntPtr LastSession;
        internal byte[]? LastBuffer;
        public int Initialize(string name, out IntPtr context)
        { if (MissingLibrary) throw new DllNotFoundException(); context = Context; return InitializeResult; }
        public int OpenSession(IntPtr context, out IntPtr session)
        { SessionCalls++; if (MissingSessionEntryPoint) throw new EntryPointNotFoundException(); session = new(2); return SessionResult; }
        public int ScanBuffer(IntPtr context, byte[] buffer, string name, IntPtr session, out int result)
        { ScanCalls++; LastSession = session; LastBuffer = buffer; result = Verdict; return ScanResult; }
        public void CloseSession(IntPtr context, IntPtr session) => CloseCalls++;
        public void Uninitialize(IntPtr context) => UninitializeCalls++;
    }
}

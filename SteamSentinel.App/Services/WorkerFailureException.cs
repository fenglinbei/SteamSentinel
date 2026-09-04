using System.ComponentModel;

namespace SteamSentinel.App.Services;

internal enum WorkerStage { Preflight, RestrictedStart, Handshake, Scanning, Exit }

internal sealed class WorkerFailureException : Exception
{
    public WorkerStage Stage { get; }
    public int? NativeExitCode { get; }
    public bool BeforeScan => Stage is WorkerStage.Preflight or WorkerStage.RestrictedStart or WorkerStage.Handshake;

    internal WorkerFailureException(WorkerStage stage, int? exitCode, string detail, Exception? inner = null)
        : base(Describe(stage, exitCode, detail, inner), inner)
    {
        Stage = stage;
        NativeExitCode = exitCode;
    }

    private static string Describe(WorkerStage stage, int? code, string detail, Exception? inner)
    {
        string phase = stage switch
        {
            WorkerStage.Preflight => "检查组件",
            WorkerStage.RestrictedStart => "创建受限进程",
            WorkerStage.Handshake => "等待安全握手",
            WorkerStage.Scanning => "读取扫描内容",
            _ => "等待扫描组件退出"
        };
        string reason = code is int value
            ? $"，退出码 0x{unchecked((uint)value):X8}" : "，未取得退出码";
        if (inner is Win32Exception win32) reason += $"，Windows 错误 {win32.NativeErrorCode}";
        string advice = code == unchecked((int)0xC0000142)
            ? "组件在初始化阶段失败，可能与受限进程权限或启动环境有关，请导出报告反馈，不要直接关闭防护。"
            : stage == WorkerStage.Preflight
                ? "请核对安装包与组件文件，必要时查看安全软件保护历史并修复安装。"
                : "请导出报告，并提供当前权限状态和复现步骤，不要仅凭此错误认定文件被杀毒软件删除。";
        return $"内容扫描{(stage is WorkerStage.Preflight or WorkerStage.RestrictedStart or WorkerStage.Handshake ? "未能启动" : "未能完成")}。阶段：{phase}{reason}。\n{Limit(detail)}\n{advice}";
    }

    internal static string Limit(string text)
    {
        string clean = string.Concat(text.Where(c => !char.IsControl(c) || c is '\n' or '\r' or '\t'));
        return clean.Length <= 2048 ? clean.Trim() : clean[..2048].Trim() + "…（已截断）";
    }
}

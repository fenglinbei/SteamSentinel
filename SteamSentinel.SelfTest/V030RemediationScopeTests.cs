using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestV030RemediationScope()
    {
        const string windows = @"C:\Windows";
        const string state = @"C:\ProgramData\SteamSentinel";
        const string application = @"C:\Program Files\SteamSentinel";
        const string user = @"C:\Users\ScopeFixture";
        const string unknownHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const string knownHash = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        RuleSet rules = new()
        {
            KnownPathTemplates = [@"C:\ProgramData\KnownFixture"],
            KnownHashes = [new() { Sha256 = knownHash, Malware = true },
                new() { Sha256 = unknownHash, Malware = false, Remediable = true }]
        };
        SteamLayout layout = new();
        layout.SteamRoots.Add(@"D:\Steam");
        layout.LibraryRoots.Add(@"E:\SteamLibrary");
        layout.WorkshopRoots.Add(@"F:\OnlyWorkshop");
        bool Allowed(string path, string? hash = unknownHash, string profile = user) =>
            FileRemediationScope.IsAllowed(path, hash, rules, layout, windows, state, application, profile);

        Check("0.3.0 隔离范围：自选扫描目录不自动获得未知文件处置权限", !Allowed(@"D:\Downloads\unknown.bin"));
        Finding clientClaim = new() { Target = @"D:\Downloads\unknown.bin", Sha256 = unknownHash, IsKnownMalware = true, CanRemediate = true };
        Check("0.3.0 隔离范围：客户端恶意标志不能代替规则库恶意哈希", !Allowed(clientClaim.Target, clientClaim.Sha256));
        Check("0.3.0 隔离范围：规则库非恶意可处置标记不扩大范围", !Allowed(@"D:\Downloads\fixture.bin", unknownHash));
        Check("0.3.0 隔离范围：规则库已知恶意哈希保留现有跨目录例外", Allowed(@"D:\Downloads\known.bin", knownHash.ToLowerInvariant()));
        Check("0.3.0 隔离范围：缺失或无效哈希不能获得跨目录例外", !Allowed(@"D:\Downloads\unknown.bin", null) && !Allowed(@"D:\Downloads\unknown.bin", "invalid"));
        Check("0.3.0 隔离范围：当前用户及已知落点保持允许", Allowed(user + @"\Downloads\inert.bin") && Allowed(@"C:\ProgramData\KnownFixture\inert.bin"));
        Check("0.3.0 隔离范围：Steam客户端和库根保持允许", Allowed(@"D:\Steam\inert.bin") && Allowed(@"E:\SteamLibrary\inert.bin"));
        Check("0.3.0 隔离范围：不新增单独工坊根白名单", !Allowed(@"F:\OnlyWorkshop\inert.bin"));
        Check("0.3.0 隔离范围：根前缀相似目录不是其子目录", !Allowed(@"D:\SteamOther\inert.bin") && !Allowed(user + @"Other\inert.bin") && !Allowed(@"C:\ProgramData\KnownFixtureOther\inert.bin"));
        Check("0.3.0 隔离范围：规范化父目录后重新判断", !Allowed(@"D:\Steam\..\Downloads\inert.bin") && Allowed(@"E:\SteamLibrary\game\..\inert.bin"));
        Check("0.3.0 隔离范围：大小写和结尾分隔符保持原语义", Allowed(@"d:\steam\INERT.bin") && Allowed(@"D:\Steam\"));
        Check("0.3.0 隔离范围：已知恶意哈希不能覆盖受保护根", !Allowed(windows + @"\inert.bin", knownHash) && !Allowed(state + @"\inert.bin", knownHash) && !Allowed(application + @"\inert.bin", knownHash));
        Check("0.3.0 隔离范围：跨账户上下文必须分别判断", Allowed(user + @"\inert.bin") && !Allowed(user + @"\inert.bin", profile: @"C:\Users\OtherAdministrator"));

        MessageText detail = MessageText.Create("Remediation.FileScopeNotApproved", clientClaim.Target);
        string zh, en;
        using (DisplayText.UseCulture(DisplayText.Chinese)) zh = detail.Display;
        using (DisplayText.UseCulture(DisplayText.English)) en = detail.Display;
        Check("0.3.0 隔离范围：未纳入说明有稳定消息身份和双语文本", detail.Message?.MessageId == "Remediation.FileScopeNotApproved" && zh != en &&
            zh.Contains("自动隔离允许范围", StringComparison.Ordinal) && en.Contains("automatic quarantine scope", StringComparison.Ordinal));

        RemediationBatchSession preview = new()
        {
            Targets = [new() { Target = clientClaim.Target, RequiredActions = ["QuarantineFile|inert-target"] }],
            PreparationNotes = Enumerable.Range(0, 6).Select(_ => new RemediationPreparationNote(clientClaim.Target,
                ReasonCodes.EvidenceUnavailable, "Earlier inert verification context")).ToList()
        };
        preview.PreparationNotes.Add(new(clientClaim.Target, ReasonCodes.ActionsNotIncluded, detail));
        RemediationBatchPlanner.MapOutcomes(preview);
        Check("0.3.0 隔离范围：预览保留明确未纳入原因且不被早期核验说明淹没", preview.Targets.Single().State == RemediationTargetState.NotIncluded &&
            preview.Targets.Single().ReasonCode == ReasonCodes.ActionsNotIncluded && preview.FailedCount == 0 &&
            preview.Targets.Single().ReasonDetailsText.OriginalText.Contains("自动隔离允许范围", StringComparison.Ordinal));
    }
}

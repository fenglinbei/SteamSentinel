using System.Text.Json;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static void TestV0119PasswordBoundaries()
    {
        ArchivePasswordResponse response = new("bounded-test", false, "legacy-inert", false,
            ArchivePasswordReuseScope.ArchiveTree, [" alpha ", "alpha", "Alpha", " alpha ", "", null!]);
        Check("0.1.19 密码输入保留空格大小写顺序并精确去重",
            ArchivePasswordInput.ValidateAndGetPasswords(response).SequenceEqual(new[] { " alpha ", "alpha", "Alpha" }));
        Check("0.1.19 非空候选列表优先于旧单密码字段",
            !ArchivePasswordInput.ValidateAndGetPasswords(response).Contains("legacy-inert"));
        Check("0.1.19 空候选列表兼容原单密码字段",
            ArchivePasswordInput.ValidateAndGetPasswords(response with { Passwords = ["", null!] }).SequenceEqual(new[] { "legacy-inert" }));
        Check("0.1.19 仅空格也是有效密码而非跳过",
            ArchivePasswordInput.ValidateAndGetPasswords(response with { Password = "  ", Passwords = null }).Single() == "  ");
        Check("0.1.19 密码长度和数量边界不截断合法输入",
            ArchivePasswordInput.ValidateAndGetPasswords(response with
            {
                Password = null,
                Passwords = Enumerable.Range(0, 16).Select(i => i.ToString("D2") + new string('x', 1022)).ToArray()
            }).Count == 16);

        const string sensitive = "inert-value-never-echo";
        bool Rejects(ArchivePasswordResponse invalid)
        {
            try { ArchivePasswordInput.ValidateAndGetPasswords(invalid); return false; }
            catch (ArgumentException ex) { return !ex.Message.Contains(sensitive, StringComparison.Ordinal); }
        }
        Check("0.1.19 拒绝超量候选而不把候选值写入错误",
            Rejects(response with { Passwords = Enumerable.Repeat(sensitive, 17).ToArray() }));
        Check("0.1.19 拒绝过长单密码而不把密码写入错误",
            Rejects(response with { Password = sensitive + new string('x', 1024) }));
        Check("0.1.19 拒绝过长批量密码而不静默截断",
            Rejects(response with { Passwords = [sensitive + new string('x', 1024)] }));
        Check("0.1.19 密码作用域拒绝未定义枚举值",
            Rejects(response with { ReuseScope = (ArchivePasswordReuseScope)999 }));
        ArchivePasswordResponse wire = JsonSerializer.Deserialize<ArchivePasswordResponse>(
            JsonSerializer.Serialize(response with { SkipAllEncrypted = true }, JsonFile.Options), JsonFile.Options)!;
        Check("0.1.19 密码消息往返保留候选顺序作用域与跳过全部标志",
            wire.SkipAllEncrypted && wire.ReuseScope == ArchivePasswordReuseScope.ArchiveTree &&
            ArchivePasswordInput.ValidateAndGetPasswords(wire).SequenceEqual(new[] { " alpha ", "alpha", "Alpha" }));
        Check("0.1.19 旧密码响应默认不启用候选列表或跳过全部",
            new ArchivePasswordResponse("legacy", true, null, false) is { Passwords: null, SkipAllEncrypted: false });
    }
}

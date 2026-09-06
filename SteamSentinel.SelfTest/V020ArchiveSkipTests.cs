using System.IO;
using System.Security.Cryptography;
using System.Text;
using SharpCompress.Common;
using SharpCompress.Readers;
using SteamSentinel.Core.Inspection;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestV020ZipSkippingAsync(string root)
    {
        // Fixed inert fixture made with the already installed 7-Zip 19.00 (7z.exe is unsigned):
        // 7z a -tzip -mem=ZipCrypto -mx=0 -pSteamSentinel-Inert-ZipSkip-020 fixture.zip
        //     01-inert-large.txt 02-inert-small.txt
        // The first plaintext is 512 bytes of repeating ASCII A..Z; the second is the 32 bytes below.
        // Both records are encrypted. The fixture was independently checked with 7z t;
        // neither the test nor fixture generation executes any archive member.
        const string password = "SteamSentinel-Inert-ZipSkip-020";
        const string fixtureBase64 =
            "UEsDBBQAAQAAAK6wJl32JH4EDAIAAAACAAASAAAAMDEtaW5lcnQtbGFyZ2UudHh00rXvwSsnz4Nr64Vi9ZX+XJb3taCaL5H60SG1mwRAbO9vglKXhnCVlWzw6FpEv3PzzCoS6AjKmn6TTy91twadcarxNvjDEyRiS7r7fJVfENHHf8cLy2ABiySJRRqL/KbhYn/f3CfXN0/BFJzGTAQeM19NwyrBZk+eygFRBqu1e5Al4wWEEsBH0NTv+SIsWKJQluJ35Xr40WmwU4s5Wwf75JBGsBIunSsyTQepO8tXSBn/obhTMSwcTEqjeYqcIvYyyvdFM3/wKzGkAN2p7giMXDvYsARqQ8Ef/axTDUahrADE3XnAgPXrnuCfeJ0z7V8OMjhlySsRoY6GAq36mQpBRppZ9Hous3W4aiVj2UXQsxwV1H3Z+2yke1BpebQ+FN9MhprOBh9QjyGduz77pmgDzw0ReYYP/AU9DCs0yNrxqWkczd2ML2DM+KRUDgoIgChEFv6bkICV0MsTJkr0xiSTi14V2d7nMXZKaciJhegnmCn3C+6hy0N3rOb7dtX0Tcfr7V9cp4GGZAwcq3bPl6P0RSmhLWXK20gpg4k1LONptWR7ewCt8MxN9SceQFMBWGdWRTBdO4Veak8dSBY8EEj5cq8aXHWlE5WQCtvaK186eCCVY2JUbQHIwanhVPW6KXha3NwOZFV5XmuSX0wxUH1vByju9O2nExU0Yrfyr7ClH3azrpq7+5yA8HJNYpxQSwMEFAABAAAArrAmXe/6T20sAAAAIAAAABIAAAAwMi1pbmVydC1zbWFsbC50eHT3pE80Z647j2R3k6jh/fac6M0uFU4yv3DEa26GWiJNE3+hZJ1wLA2NyrViPlBLAQI/ABQAAQAAAK6wJl32JH4EDAIAAAACAAASACQAAAAAAAAAIAAAAAAAAAAwMS1pbmVydC1sYXJnZS50eHQKACAAAAAAAAEAGAAqxZ3ECD7dASrFncQIPt0Bqp2dxAg+3QFQSwECPwAUAAEAAACusCZd7/pPbSwAAAAgAAAAEgAkAAAAAAAAACAAAAA8AgAAMDItaW5lcnQtc21hbGwudHh0CgAgAAAAAAABABgAO+ydxAg+3QE77J3ECD7dASrFncQIPt0BUEsFBgAAAAACAAIAyAAAAJgCAAAAAA==";
        byte[] fixture = Convert.FromBase64String(fixtureBase64);
        byte[] expected = Encoding.ASCII.GetBytes("SteamSentinel inert second item.");
        Check("0.2.0 ZIP跳过固定加密样本身份与次项长度",
            Convert.ToHexString(SHA256.HashData(fixture)) == "04A72C03AB5C6E649FEF2FF291CCE7DDCA5CA8AC216780DB3F640A7BD1C70DD8" &&
            expected.Length == 32);
        string directory = Path.Combine(root, "v020-zip-skipping"); Directory.CreateDirectory(directory);
        ArchiveVolumeCandidate candidate = new(Path.Combine(directory, "encrypted-two-members.zip"), "encrypted-two-members.zip");
        await File.WriteAllBytesAsync(candidate.PhysicalPath, fixture);
        ArchiveVolumePlan plan = ArchiveVolumeResolver.Single(candidate, ArchiveVolumeFormat.Zip);

        long reads = 0;
        using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(plan, password,
            readDecorator: source => new V020CountedSource(source, count => reads += count)))
        {
            Check("0.2.0 ZIP遍历开始前不能跳过", !session.CanSkipCurrentUnopenedEntry && session.SkippedEntries == 0);
            using IReader reader = session.OpenReader();
            try
            {
                bool firstAvailable = reader.MoveToNextEntry();
                IEntry first = reader.Entry;
                Check("0.2.0 ZIP未打开的大首项可显式跳过",
                    firstAvailable && first.Key == "01-inert-large.txt" && first.Size == 512 && first.IsEncrypted &&
                    session.CanSkipCurrentUnopenedEntry);
                long beforeSkip = reads;
                session.SkipCurrentUnopenedEntry(first);
                Check("0.2.0 ZIP显式跳过不打开解码流也不增加源读取",
                    reads == beforeSkip && session.SkippedEntries == 1 && !session.CanSkipCurrentUnopenedEntry);
                Check("0.2.0 ZIP同一成员不能重复登记跳过",
                    RejectInvalidOperation(() => session.SkipCurrentUnopenedEntry(first)) && session.SkippedEntries == 1);

                bool secondAvailable = reader.MoveToNextEntry();
                IEntry second = reader.Entry;
                Check("0.2.0 ZIP跳过首项后可定位独立的小次项",
                    secondAvailable && second.Key == "02-inert-small.txt" && second.Size == expected.Length &&
                    second.IsEncrypted && session.CanSkipCurrentUnopenedEntry);
                Check("0.2.0 ZIP不能用旧成员对象跳过当前次项",
                    RejectInvalidOperation(() => session.SkipCurrentUnopenedEntry(first)) &&
                    session.SkippedEntries == 1 && session.CanSkipCurrentUnopenedEntry);

                using (ArchiveIntegrityEntryVerifier verifier = ArchiveIntegrity.Begin(session, second))
                {
                    Check("0.2.0 ZIP跳过未把未校验次项当作密码成功", !verifier.CanValidatePassword);
                    using Stream input = reader.OpenEntryStream();
                    try
                    {
                        Check("0.2.0 ZIP已打开成员不能再登记跳过",
                            !session.CanSkipCurrentUnopenedEntry &&
                            RejectInvalidOperation(() => session.SkipCurrentUnopenedEntry(second)) && session.SkippedEntries == 1);
                        using MemoryStream output = new();
                        using SharpCompress.Crypto.Crc32Stream crc = new(output);
                        await input.CopyToAsync(crc, 17);
                        verifier.Complete(input, output.Length, crc.Crc);
                        Check("0.2.0 ZIP跳过大首项后小次项完整CRC和密码验证成功",
                            output.ToArray().SequenceEqual(expected) && verifier.CanValidatePassword);
                    }
                    catch { reader.Cancel(); throw; }
                }
                Check("0.2.0 ZIP跳过遍历确实到达目录EOF", !reader.MoveToNextEntry() && !session.CanSkipCurrentUnopenedEntry);
                Check("0.2.0 ZIP有显式跳过时默认完整性完成必须拒绝",
                    RejectIncomplete(() => session.VerifyTraversalCompleted()));
                session.VerifyTraversalCompleted(allowSkipped: true);
                Check("0.2.0 ZIP显式允许跳过只确认已验证和已跳过计数守恒", session.SkippedEntries == 1);
            }
            catch { reader.Cancel(); throw; }
        }

        // Merely advancing past a file is not the explicit, audited skip operation.
        using (ArchiveVolumeSession session = await ArchiveVolumeSession.OpenAsync(plan, password))
        {
            using IReader reader = session.OpenReader();
            try
            {
                bool firstAvailable = reader.MoveToNextEntry();
                bool secondAvailable = reader.MoveToNextEntry();
                Check("0.2.0 ZIP对照遍历包含两项且未登记跳过", firstAvailable && secondAvailable && session.SkippedEntries == 0);
                using (ArchiveIntegrityEntryVerifier verifier = ArchiveIntegrity.Begin(session, reader.Entry))
                {
                    using Stream input = reader.OpenEntryStream();
                    try
                    {
                        using MemoryStream output = new();
                        using SharpCompress.Crypto.Crc32Stream crc = new(output);
                        await input.CopyToAsync(crc, 17);
                        verifier.Complete(input, output.Length, crc.Crc);
                    }
                    catch { reader.Cancel(); throw; }
                }
                bool reachedEnd = !reader.MoveToNextEntry();
                Check("0.2.0 ZIP允许跳过参数不能掩盖未登记也未验证的首项",
                    reachedEnd && RejectIncomplete(() => session.VerifyTraversalCompleted(allowSkipped: true)));
            }
            catch { reader.Cancel(); throw; }
        }

        static bool RejectInvalidOperation(Action action)
        {
            try { action(); return false; }
            catch (InvalidOperationException) { return true; }
        }
        static bool RejectIncomplete(Action action)
        {
            try { action(); return false; }
            catch (ArchiveVolumeException exception) { return exception.Reason == ArchiveVolumeStatus.InvalidMetadata; }
        }
    }
}

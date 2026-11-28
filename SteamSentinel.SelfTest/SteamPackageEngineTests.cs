using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using SharpCompress.Compressors.LZMA;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    /// <summary>验证 Steam 官方分包目录解析、.installed 自校验、.zip.vz/.zip 安全提取与受控 CDN 补拉。</summary>
    internal static async Task TestSteamPackageEngineAsync(string root)
    {
        string workDir = Path.Combine(root, "steam-package-engine");
        Directory.CreateDirectory(workDir);

        // 1. 纯 C# IEEE 802.3 CRC32 标准向量校验
        Check("分包引擎 IEEE 802.3 CRC32 标准向量正确",
            SteamPackageArchive.ComputeCrc32("123456789"u8) == 0xCBF43926u &&
            SteamPackageArchive.ComputeCrc32([]) == 0u);

        // 2. 构造真实 ZIP 与 .zip.vz 夹具
        byte[] jsBytes = "console.log('SteamSentinel official steamui fixture');\n"u8.ToArray();
        byte[] htmlBytes = "<html><body>official clientui</body></html>"u8.ToArray();
        byte[] resBytes = "/* official webkit.css */"u8.ToArray();
        byte[] exeBytes = "MZ_OFFICIAL_STEAM_EXE_FIXTURE"u8.ToArray();

        byte[] steamUiZip = CreateZipBytes(("steamui/103.js", jsBytes));
        byte[] steamUiVz = CreateVzBytes(steamUiZip);
        string steamUiZipSha = Hashing.Sha256Bytes(steamUiZip);
        string steamUiVzSha = Hashing.Sha256Bytes(steamUiVz);

        byte[] publicZip = CreateZipBytes(("clientui/index.html", htmlBytes));
        byte[] publicVz = CreateVzBytes(publicZip);
        string publicZipSha = Hashing.Sha256Bytes(publicZip);
        string publicVzSha = Hashing.Sha256Bytes(publicVz);

        byte[] resourceZip = CreateZipBytes(("resource/webkit.css", resBytes));
        string resourceZipSha = Hashing.Sha256Bytes(resourceZip);

        byte[] steamExeZip = CreateZipBytes(("steam.exe", exeBytes));
        byte[] steamExeVz = CreateVzBytes(steamExeZip);
        string steamExeZipSha = Hashing.Sha256Bytes(steamExeZip);
        string steamExeVzSha = Hashing.Sha256Bytes(steamExeVz);

        // 3. 构造完整 Steam 夹具目录（含 manifest 与带 SHA1 自校验的 .installed）
        string steamRoot = Path.Combine(workDir, "steam-valid");
        string pkgDir = Path.Combine(steamRoot, "package");
        Directory.CreateDirectory(pkgDir);

        const string steamUiZipName = "steamui_websrc_all.zip.1111111111111111111111111111111111111111";
        const string steamUiVzName = "steamui_websrc_all.zip.vz.2222222222222222222222222222222222222222_123";
        const string publicZipName = "public_all.zip.3333333333333333333333333333333333333333";
        const string publicVzName = "public_all.zip.vz.4444444444444444444444444444444444444444_123";
        const string resourceZipName = "resources_all.zip.5555555555555555555555555555555555555555";
        const string steamExeZipName = "steam_win64.zip.6666666666666666666666666666666666666666";
        const string steamExeVzName = "steam_win64.zip.vz.7777777777777777777777777777777777777777_123";
        const string steamRowZipName = "steam_win64_steamrow.zip.6666666666666666666666666666666666666666";
        const string steamRowVzName = "steam_win64_steamrow.zip.vz.7777777777777777777777777777777777777777_123";
        const string steamChinaZipName = "steam_win64_steamchina.zip.8888888888888888888888888888888888888888";

        string dummySha = new('A', 64);
        string manifestText =
            $$"""
            "win64"
            {
                "version"        "1794536281"
                "ostype"        "win10"
                "tenfoot_images_all"
                {
                    "file"        "tenfoot_images_all.zip.0001"
                    "size"        "100"
                    "sha2"        "{{dummySha}}"
                }
                "steamui_websrc_movies_all"
                {
                    "file"        "steamui_websrc_movies_all.zip.0002"
                    "size"        "100"
                    "sha2"        "{{dummySha}}"
                }
                "steamui_websrc_sounds_all"
                {
                    "file"        "steamui_websrc_sounds_all.zip.0003"
                    "size"        "100"
                    "sha2"        "{{dummySha}}"
                }
                "bins_cef_win64"
                {
                    "file"        "bins_cef_win64.zip.0004"
                    "size"        "148409167"
                    "sha2"        "{{dummySha}}"
                    "zipvz"        "bins_cef_win64.zip.vz.0004_106055291"
                    "sha2vz"        "{{dummySha}}"
                }
                "steamui_websrc_all"
                {
                    "file"        "{{steamUiZipName}}"
                    "size"        "{{steamUiZip.Length}}"
                    "sha2"        "{{steamUiZipSha}}"
                    "zipvz"        "{{steamUiVzName}}"
                    "sha2vz"        "{{steamUiVzSha}}"
                }
                "public_all"
                {
                    "file"        "{{publicZipName}}"
                    "size"        "{{publicZip.Length}}"
                    "sha2"        "{{publicZipSha}}"
                    "zipvz"        "{{publicVzName}}"
                    "sha2vz"        "{{publicVzSha}}"
                }
                "resources_all"
                {
                    "file"        "{{resourceZipName}}"
                    "size"        "{{resourceZip.Length}}"
                    "sha2"        "{{resourceZipSha}}"
                }
                "resources_misc_all"
                {
                    "file"        "resources_misc_all.zip.0005"
                    "size"        "100"
                    "sha2"        "{{dummySha}}"
                }
                "resources_hidpi_all"
                {
                    "file"        "resources_hidpi_all.zip.0006"
                    "size"        "100"
                    "sha2"        "{{dummySha}}"
                }
                "bins_win64"
                {
                    "file"        "bins_win64.zip.0007"
                    "size"        "100"
                    "sha2"        "{{dummySha}}"
                }
                "steam_win64"
                {
                    "steamrow"
                    {
                        "file"        "{{steamRowZipName}}"
                        "size"        "{{steamExeZip.Length}}"
                        "sha2"        "{{steamExeZipSha}}"
                        "zipvz"        "{{steamRowVzName}}"
                        "sha2vz"        "{{steamExeVzSha}}"
                        "IsBootstrapperPackage"        "1"
                    }
                    "steamchina"
                    {
                        "file"        "{{steamChinaZipName}}"
                        "size"        "200"
                        "sha2"        "{{dummySha}}"
                        "IsBootstrapperPackage"        "1"
                    }
                    "file"        "{{steamExeZipName}}"
                    "size"        "{{steamExeZip.Length}}"
                    "sha2"        "{{steamExeZipSha}}"
                    "zipvz"        "{{steamExeVzName}}"
                    "sha2vz"        "{{steamExeVzSha}}"
                    "IsBootstrapperPackage"        "1"
                }
            }
            "kvsign2"
            {
                "win64"        "deadbeef"
            }
            """;

        string manifestPath = Path.Combine(pkgDir, "steam_client_win64.manifest");
        await File.WriteAllTextAsync(manifestPath, manifestText.Replace("    ", "\t", StringComparison.Ordinal), new UTF8Encoding(false));

        // 构造较低优先级的 win32/publicbeta 清单以验证加载优先级
        await File.WriteAllTextAsync(
            Path.Combine(pkgDir, "steam_client_win32.manifest"),
            manifestText.Replace("\"win64\"", "\"win32\""),
            new UTF8Encoding(false));
        await File.WriteAllTextAsync(
            Path.Combine(pkgDir, "steam_client_publicbeta_win64.manifest"),
            manifestText,
            new UTF8Encoding(false));

        // 构造含 CRLF、目录行（size == -1）及真实 SHA1 尾标的 .installed 文件
        uint jsCrc = SteamPackageArchive.ComputeCrc32(jsBytes);
        uint exeCrc = SteamPackageArchive.ComputeCrc32(exeBytes);
        string installedBodyLf =
            $"bin\\,-1;1794535550;0\n" +
            $"steam.exe,{exeBytes.Length};1794535550;{exeCrc}\n" +
            $"steamui\\103.js,{jsBytes.Length};1794535550;{jsCrc}\n" +
            $"clientui\\index.html,{htmlBytes.Length};1794535550;{SteamPackageArchive.ComputeCrc32(htmlBytes)}\n" +
            $"resource\\webkit.css,{resBytes.Length};1794535550;{SteamPackageArchive.ComputeCrc32(resBytes)}\n" +
            $"OSVER=20\nVERSION=3\n";
        string installedSha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(installedBodyLf)));
        string installedFullCrlf = (installedBodyLf + $"SHA1={installedSha1}\n").Replace("\n", "\r\n", StringComparison.Ordinal);
        string installedPath = Path.Combine(pkgDir, "steam_client_win64.installed");
        await File.WriteAllTextAsync(installedPath, installedFullCrlf, new UTF8Encoding(false));

        // 本地放入 steamui .zip.vz、resources .zip、steam_win64_steamrow .zip.vz（模拟真机只存 steamrow 子变体）
        string localSteamUiVzPath = Path.Combine(pkgDir, steamUiVzName);
        string localResourceZipPath = Path.Combine(pkgDir, resourceZipName);
        string localSteamRowVzPath = Path.Combine(pkgDir, steamRowVzName);
        await File.WriteAllBytesAsync(localSteamUiVzPath, steamUiVz);
        await File.WriteAllBytesAsync(localResourceZipPath, resourceZip);
        await File.WriteAllBytesAsync(localSteamRowVzPath, steamExeVz);

        bool loaded = SteamPackageCatalog.TryLoadForSteamRoot(steamRoot, out SteamPackageCatalog? catalog);
        Check("分包引擎 成功加载优先清单 win64 与通过自校验的 .installed",
            loaded && catalog is not null &&
            Path.GetFileName(catalog.ManifestPath) == "steam_client_win64.manifest" &&
            catalog.PlatformKey == "win64" &&
            catalog.ClientVersion == "1794536281" &&
            catalog.HasVerifiedInstalledIndex &&
            catalog.InstalledFiles.Count == 4);

        Check("分包引擎 正确区分 steam_win64 与 steamrow/steamchina 子节点",
            catalog is not null &&
            catalog.TryGetPackage("steam_win64", out SteamPackageEntry? steamMain) &&
            steamMain.IsBootstrapperPackage &&
            steamMain.ZipFile == steamExeZipName &&
            catalog.TryGetPackage("steam_win64_steamrow", out SteamPackageEntry? steamRow) &&
            steamRow.ZipVzFile == steamRowVzName &&
            catalog.TryGetPackage("steam_win64_steamchina", out SteamPackageEntry? steamChina) &&
            steamChina.ZipFile == steamChinaZipName);

        Check("分包引擎 .installed 相对路径查询支持正反斜杠大小写并拒绝目录行与穿越",
            catalog is not null &&
            catalog.IsKnownOfficialRelativePath(@"steamui\103.JS") &&
            catalog.IsKnownOfficialRelativePath("steam.exe") &&
            !catalog.IsKnownOfficialRelativePath("bin") &&
            !catalog.IsKnownOfficialRelativePath("../steamui/103.js") &&
            catalog.TryGetInstalledEntry("steamui/103.js", out SteamInstalledFileEntry? jsEntry) &&
            jsEntry.Size == jsBytes.Length && jsEntry.Crc32 == jsCrc &&
            catalog.TryGetInstalledEntry(@"bin\", out SteamInstalledFileEntry? dirEntry) &&
            dirEntry.IsDirectory && dirEntry.Size == -1);

        // 4. 分包候选智能路由检查
        if (catalog is not null)
        {
            IReadOnlyList<SteamPackageEntry> uiRoute = catalog.OrderCandidatePackages("steamui/103.js");
            IReadOnlyList<SteamPackageEntry> clientRoute = catalog.OrderCandidatePackages(@"clientui\index.html");
            IReadOnlyList<SteamPackageEntry> resRoute = catalog.OrderCandidatePackages("resource/webkit.css");
            IReadOnlyList<SteamPackageEntry> exeRoute = catalog.OrderCandidatePackages("steam.exe");

            Check("分包引擎 steamui/* 路由顺序且排除纯媒体与置后 CEF",
                uiRoute.Count >= 3 &&
                uiRoute[0].Name == "steamui_websrc_all" &&
                uiRoute[1].Name == "public_all" &&
                uiRoute[^1].Name.StartsWith("bins_cef", StringComparison.Ordinal) &&
                !uiRoute.Any(p => p.Name is "steamui_websrc_movies_all" or "steamui_websrc_sounds_all" or "tenfoot_images_all"));

            Check("分包引擎 clientui/* 优先 public_all 与 steamui_websrc_all",
                clientRoute.Count >= 3 &&
                clientRoute[0].Name == "public_all" &&
                clientRoute[1].Name == "steamui_websrc_all" &&
                clientRoute[^1].Name.StartsWith("bins_cef", StringComparison.Ordinal));

            Check("分包引擎 resource/* 优先 resources_all/misc/hidpi/public_all",
                resRoute.Count >= 5 &&
                resRoute[0].Name == "resources_all" &&
                resRoute[1].Name == "resources_misc_all" &&
                resRoute[2].Name == "resources_hidpi_all" &&
                resRoute[3].Name == "public_all" &&
                resRoute[^1].Name.StartsWith("bins_cef", StringComparison.Ordinal));

            Check("分包引擎 steam.exe 优先 steam_win64 与 bins_win64",
                exeRoute.Count >= 5 &&
                exeRoute[0].Name == "steam_win64" &&
                exeRoute.Any(p => p.Name == "bins_win64") &&
                Array.FindIndex(exeRoute.ToArray(), p => p.Name == "bins_win64") < exeRoute.Count - 1 &&
                exeRoute[^1].Name.StartsWith("bins_cef", StringComparison.Ordinal));

            Check("分包引擎 路由与根目录校验拒绝 .. 路径穿越及 UNC",
                catalog.OrderCandidatePackages("../steam.exe").Count == 0 &&
                catalog.OrderCandidatePackages(@"C:\steam.exe").Count == 0 &&
                !SteamPackageCatalog.TryLoadForSteamRoot(@"\\evil.invalid\share\steam", out _) &&
                !SteamPackageCatalog.TryLoadForSteamRoot(Path.Combine(workDir, "missing-steam-root"), out _));

            // 5. 正向离线提取（.zip.vz、普通 .zip、以及子变体 steam_win64_steamrow）
            SteamPackageExtractResult? extractedVz = await SteamPackageArchive.TryExtractOfficialFileAsync(
                catalog, @"steamui\103.JS", allowDownload: false);
            Check("分包引擎 离线从 .zip.vz 提取文件并校验哈希成功",
                extractedVz is not null &&
                !extractedVz.Downloaded &&
                extractedVz.RelativePath == "steamui/103.js" &&
                extractedVz.SourcePackage.Name == "steamui_websrc_all" &&
                extractedVz.Content.SequenceEqual(jsBytes) &&
                extractedVz.Sha256 == Hashing.Sha256Bytes(jsBytes));

            SteamPackageExtractResult? extractedZip = await SteamPackageArchive.TryExtractOfficialFileAsync(
                catalog, "resource/webkit.css", allowDownload: false);
            Check("分包引擎 离线从普通 .zip 提取文件成功",
                extractedZip is not null &&
                !extractedZip.Downloaded &&
                extractedZip.SourcePackage.Name == "resources_all" &&
                extractedZip.Content.SequenceEqual(resBytes));

            SteamPackageExtractResult? extractedExe = await SteamPackageArchive.TryExtractOfficialFileAsync(
                catalog, "steam.exe", allowDownload: false);
            Check("分包引擎 离线识别真机 steam_win64_steamrow 变体提取 steam.exe",
                extractedExe is not null &&
                !extractedExe.Downloaded &&
                extractedExe.SourcePackage.Name == "steam_win64_steamrow" &&
                extractedExe.Content.SequenceEqual(exeBytes));
        }

        // 6. 优先级回退测试（仅 publicbeta 与 win32 时应选择 publicbeta）
        string betaRoot = Path.Combine(workDir, "steam-beta");
        string betaPkg = Path.Combine(betaRoot, "package");
        Directory.CreateDirectory(betaPkg);
        await File.WriteAllTextAsync(Path.Combine(betaPkg, "steam_client_win32.manifest"), manifestText.Replace("\"win64\"", "\"win32\""));
        await File.WriteAllTextAsync(Path.Combine(betaPkg, "steam_client_publicbeta_win64.manifest"), manifestText);
        Check("分包引擎 无 win64 主清单时优先选择 publicbeta_win64",
            SteamPackageCatalog.TryLoadForSteamRoot(betaRoot, out SteamPackageCatalog? betaCat) &&
            Path.GetFileName(betaCat.ManifestPath) == "steam_client_publicbeta_win64.manifest");

        // 7. 负面防篡改测试：manifest 路径穿越 / 超限 / 篡改 .installed
        string badManifestDir = Path.Combine(workDir, "bad-manifest", "package");
        Directory.CreateDirectory(badManifestDir);
        foreach (string unsafeName in new[] { "../evil.zip", "sub/evil.zip", @"sub\evil.zip", @"sub\\evil.zip", "C:evil.zip", "evil\0.zip" })
        {
            string badVdf = manifestText.Replace(steamUiZipName, unsafeName, StringComparison.Ordinal);
            Check($"分包引擎 拒绝 manifest 不安全文件名 ({unsafeName.Replace("\0", "\\0", StringComparison.Ordinal)})",
                !SteamPackageCatalog.TryParseManifestText(badVdf, out _, out _, out _, out _));
        }

        string oversizeRoot = Path.Combine(workDir, "oversize-manifest");
        string oversizePkg = Path.Combine(oversizeRoot, "package");
        Directory.CreateDirectory(oversizePkg);
        await using (FileStream bigFs = File.Create(Path.Combine(oversizePkg, "steam_client_win64.manifest")))
        {
            bigFs.SetLength(SteamPackageCatalog.MaximumManifestBytes + 1);
        }
        Check("分包引擎 拒绝超过 8 MiB 的 manifest 文件",
            !SteamPackageCatalog.TryLoadForSteamRoot(oversizeRoot, out _));

        string tamperedInstalledRoot = Path.Combine(workDir, "tampered-installed");
        string tamperedPkg = Path.Combine(tamperedInstalledRoot, "package");
        Directory.CreateDirectory(tamperedPkg);
        await File.WriteAllTextAsync(Path.Combine(tamperedPkg, "steam_client_win64.manifest"), manifestText);
        await File.WriteAllTextAsync(
            Path.Combine(tamperedPkg, "steam_client_win64.installed"),
            installedFullCrlf.Replace("steamui\\103.js", "steamui\\999.js", StringComparison.Ordinal));
        Check("分包引擎 篡改 .installed 内容导致 SHA1 自校验失效且不信任条目",
            SteamPackageCatalog.TryLoadForSteamRoot(tamperedInstalledRoot, out SteamPackageCatalog? tamperedCat) &&
            !tamperedCat.HasVerifiedInstalledIndex &&
            tamperedCat.InstalledFiles.Count == 0 &&
            !tamperedCat.IsKnownOfficialRelativePath("steamui/999.js"));

        // 8. 负面防篡改测试：坏 VZ 头、坏 VZ 尾、短文件、错误 sha2vz、错误 CRC32、超限拒绝、路径穿越
        SteamPackageEntry vzEntry = new("steamui_websrc_all", steamUiZipName, steamUiZip.Length, steamUiZipSha, steamUiVzName, steamUiVzSha, false);

        byte[] badHeaderVz = (byte[])steamUiVz.Clone();
        badHeaderVz[0] = (byte)'X';
        Check("分包引擎 拒绝错误 VZ 头魔数",
            await ThrowsInvalidAsync(async () =>
            {
                string p = Path.Combine(workDir, "bad-header.zip.vz");
                await File.WriteAllBytesAsync(p, badHeaderVz);
                await SteamPackageArchive.ExtractFromVzFileAsync(p, vzEntry, "steamui/103.js", Hashing.Sha256Bytes(badHeaderVz));
            }));

        byte[] badTrailerVz = (byte[])steamUiVz.Clone();
        badTrailerVz[^1] = (byte)'X';
        Check("分包引擎 拒绝错误 zv 尾魔数",
            await ThrowsInvalidAsync(async () =>
            {
                string p = Path.Combine(workDir, "bad-trailer.zip.vz");
                await File.WriteAllBytesAsync(p, badTrailerVz);
                await SteamPackageArchive.ExtractFromVzFileAsync(p, vzEntry, "steamui/103.js", Hashing.Sha256Bytes(badTrailerVz));
            }));

        byte[] shortVz = new byte[21];
        Check("分包引擎 拒绝长度不足 22 字节的 VZ 文件",
            await ThrowsInvalidAsync(async () =>
            {
                string p = Path.Combine(workDir, "short.zip.vz");
                await File.WriteAllBytesAsync(p, shortVz);
                await SteamPackageArchive.ExtractFromVzFileAsync(p, vzEntry, "steamui/103.js", Hashing.Sha256Bytes(shortVz));
            }));

        Check("分包引擎 拒绝不匹配的 sha2vz",
            await ThrowsInvalidAsync(async () =>
            {
                await SteamPackageArchive.ExtractFromVzFileAsync(localSteamUiVzPath, vzEntry, "steamui/103.js", new string('F', 64));
            }));

        byte[] badCrcVz = (byte[])steamUiVz.Clone();
        badCrcVz[^10] ^= 0xFF;
        Check("分包引擎 拒绝错误内层 ZIP CRC32",
            await ThrowsInvalidAsync(async () =>
            {
                string p = Path.Combine(workDir, "bad-crc.zip.vz");
                await File.WriteAllBytesAsync(p, badCrcVz);
                await SteamPackageArchive.ExtractFromVzFileAsync(p, vzEntry, "steamui/103.js", Hashing.Sha256Bytes(badCrcVz));
            }));

        byte[] oversizeTrailerVz = (byte[])steamUiVz.Clone();
        BinaryPrimitives.WriteUInt32LittleEndian(oversizeTrailerVz.AsSpan(oversizeTrailerVz.Length - 6, 4),
            (uint)SteamPackageArchive.MaximumUncompressedZipBytes + 1u);
        Check("分包引擎 拒绝超过 256 MiB 解压声明上限的 VZ 容器",
            await ThrowsInvalidAsync(async () =>
            {
                string p = Path.Combine(workDir, "oversize-vz.zip.vz");
                await File.WriteAllBytesAsync(p, oversizeTrailerVz);
                await SteamPackageArchive.ExtractFromVzFileAsync(p, vzEntry, "steamui/103.js", Hashing.Sha256Bytes(oversizeTrailerVz));
            }));

        Check("分包引擎 提取拒绝路径穿越相对路径",
            await ThrowsInvalidAsync(async () =>
            {
                await SteamPackageArchive.ExtractFromVzFileAsync(localSteamUiVzPath, vzEntry, "../steamui/103.js", steamUiVzSha);
            }));

        // 超过 64 MiB 单文件提取拒绝测试（高压缩全零条目仅占极少磁盘）
        byte[] overLimitEntryZip = CreateZipBytes(("steamui/huge.bin", new byte[SteamPackageArchive.MaximumExtractedFileBytes + 1]));
        string overLimitEntryZipPath = Path.Combine(workDir, "huge-entry.zip");
        await File.WriteAllBytesAsync(overLimitEntryZipPath, overLimitEntryZip);
        Check("分包引擎 拒绝提取超过 64 MiB 的单个 ZIP 条目",
            await ThrowsInvalidAsync(async () =>
            {
                await SteamPackageArchive.ExtractFromZipFileAsync(
                    overLimitEntryZipPath,
                    new SteamPackageEntry("huge", "huge.zip", overLimitEntryZip.Length, Hashing.Sha256Bytes(overLimitEntryZip), null, null, false),
                    "steamui/huge.bin",
                    Hashing.Sha256Bytes(overLimitEntryZip));
            }));

        // 9. 受控 CDN 按需补拉测试（主站 503 备站成功、非法 302 跳转拒绝、坏哈希拒绝、超 64 MiB 拒绝）
        if (catalog is not null)
        {
            SteamPackageEntry publicEntry = catalog.PackageMap["public_all"];
            List<Uri> requestedUris = [];
            using PackageMockCdnHandler fallbackHandler = new(req =>
            {
                requestedUris.Add(req.RequestUri!);
                if (req.RequestUri!.Host == "steamcdn-a.akamaihd.net")
                {
                    return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
                }

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(publicVz)
                };
            });

            SteamPackageExtractResult? cdnExtracted = await SteamPackageArchive.TryExtractOfficialFileAsync(
                catalog,
                "clientui/index.html",
                allowDownload: true,
                CancellationToken.None,
                fallbackHandler);

            Check("分包引擎 CDN 主站失败自动切换备站补拉并原子落盘提取",
                cdnExtracted is not null &&
                cdnExtracted.Downloaded &&
                cdnExtracted.SourcePackage.Name == "public_all" &&
                cdnExtracted.Content.SequenceEqual(htmlBytes) &&
                File.Exists(Path.Combine(pkgDir, publicVzName)) &&
                Directory.GetFiles(pkgDir, "*.tmp").Length == 0 &&
                requestedUris.Count == 2 &&
                requestedUris[0].Host == "steamcdn-a.akamaihd.net" &&
                requestedUris[1].Host == "cdn.akamai.steamstatic.com");

            // 非法 302 重定向拒绝
            string cdnNegDir = Path.Combine(workDir, "cdn-neg");
            Directory.CreateDirectory(cdnNegDir);
            List<Uri> redirectRequests = [];
            using PackageMockCdnHandler redirectHandler = new(req =>
            {
                redirectRequests.Add(req.RequestUri!);
                HttpResponseMessage resp = new(HttpStatusCode.Found);
                resp.Headers.Location = new Uri("https://evil.example.invalid/payload.zip");
                return resp;
            });
            string? redirectedResult = await SteamPackageArchive.TryDownloadPackageAsync(publicEntry, cdnNegDir, CancellationToken.None, redirectHandler);
            Check("分包引擎 CDN 拒绝 302 非法重定向且绝不跟进目标 URL",
                redirectedResult is null &&
                redirectRequests.All(u => u.Host is "steamcdn-a.akamaihd.net" or "cdn.akamai.steamstatic.com") &&
                !File.Exists(Path.Combine(cdnNegDir, publicVzName)));

            // 坏哈希拒绝并清理临时文件
            using PackageMockCdnHandler badHashHandler = new(_ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent("tampered-cdn-payload"u8.ToArray())
            });
            string? badHashResult = await SteamPackageArchive.TryDownloadPackageAsync(publicEntry, cdnNegDir, CancellationToken.None, badHashHandler);
            Check("分包引擎 CDN 拒绝错误哈希响应并清理临时文件",
                badHashResult is null &&
                !File.Exists(Path.Combine(cdnNegDir, publicVzName)) &&
                Directory.GetFiles(cdnNegDir, "*.tmp").Length == 0);

            // 超 64 MiB 响应流拒绝（Content-Length 与无头流式双路径）
            using PackageMockCdnHandler headerOversizeHandler = new(_ =>
            {
                HttpResponseMessage resp = new(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent([])
                };
                resp.Content.Headers.ContentLength = SteamPackageArchive.MaximumDownloadBytes + 1L;
                return resp;
            });
            string? headerOversizeResult = await SteamPackageArchive.TryDownloadPackageAsync(publicEntry, cdnNegDir, CancellationToken.None, headerOversizeHandler);
            Check("分包引擎 CDN 拒绝 Content-Length 超过 64 MiB 的响应",
                headerOversizeResult is null && Directory.GetFiles(cdnNegDir, "*.tmp").Length == 0);

            using PackageMockCdnHandler streamOversizeHandler = new(_ => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new PackageRepeatedByteStream(SteamPackageArchive.MaximumDownloadBytes + 1024))
            });
            string? streamOversizeResult = await SteamPackageArchive.TryDownloadPackageAsync(publicEntry, cdnNegDir, CancellationToken.None, streamOversizeHandler);
            Check("分包引擎 CDN 流式截断并拒绝超过 64 MiB 的无头响应",
                streamOversizeResult is null &&
                !File.Exists(Path.Combine(cdnNegDir, publicVzName)) &&
                Directory.GetFiles(cdnNegDir, "*.tmp").Length == 0);
        }

        // 10. 可选真机只读检查（绝不修改真机目录，缺失时直接跳过不阻塞 CI）
        const string liveSteamRoot = @"C:\Program Files (x86)\Steam";
        string liveManifest = Path.Combine(liveSteamRoot, "package", "steam_client_win64.manifest");
        if (File.Exists(liveManifest))
        {
            bool liveLoaded = SteamPackageCatalog.TryLoadForSteamRoot(liveSteamRoot, out SteamPackageCatalog? liveCatalog);
            Check("分包引擎 本机真实 Steam 只读加载与 .installed 自校验通过",
                liveLoaded && liveCatalog is not null &&
                liveCatalog.Packages.Count >= 10 &&
                (!File.Exists(Path.Combine(liveSteamRoot, "package", "steam_client_win64.installed")) ||
                 (liveCatalog.HasVerifiedInstalledIndex && liveCatalog.IsKnownOfficialRelativePath("steam.exe"))));

            if (liveCatalog is not null &&
                liveCatalog.TryGetPackage("steam_win64_steamrow", out SteamPackageEntry? liveRow) &&
                !string.IsNullOrEmpty(liveRow.ZipVzFile) &&
                File.Exists(Path.Combine(liveCatalog.PackageDirectory, liveRow.ZipVzFile)))
            {
                SteamPackageExtractResult? liveSteamExe = await SteamPackageArchive.TryExtractOfficialFileAsync(
                    liveCatalog, "steam.exe", allowDownload: false);
                Check("分包引擎 本机真实 .zip.vz 离线提取 steam.exe 成功且字节有效",
                    liveSteamExe is not null &&
                    !liveSteamExe.Downloaded &&
                    liveSteamExe.Content.Length > 1024 &&
                    liveSteamExe.Content[0] == (byte)'M' &&
                    liveSteamExe.Content[1] == (byte)'Z');
            }
            else
            {
                Skip("本机 Steam package 下未驻留 steam_win64_steamrow.zip.vz，跳过真机 VZ 提取检查");
            }
        }
        else
        {
            Skip("本机未检测到 C:\\Program Files (x86)\\Steam，跳过真机只读分包检查");
        }
    }

    private static byte[] CreateZipBytes(params (string EntryPath, byte[] Content)[] entries)
    {
        using MemoryStream ms = new();
        using (ZipArchive archive = new(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach ((string entryPath, byte[] content) in entries)
            {
                ZipArchiveEntry entry = archive.CreateEntry(entryPath, CompressionLevel.Fastest);
                using Stream stream = entry.Open();
                stream.Write(content, 0, content.Length);
            }
        }

        return ms.ToArray();
    }

    private static byte[] CreateVzBytes(byte[] rawZipBytes)
    {
        using MemoryStream compressed = new();
        byte[] props;
        using (LzmaStream encoder = LzmaStream.Create(new LzmaEncoderProperties(eos: true, dictionary: 1 << 16), isLzma2: false, compressed))
        {
            props = encoder.Properties;
            encoder.Write(rawZipBytes, 0, rawZipBytes.Length);
        }

        byte[] lzmaPayload = compressed.ToArray();
        uint crc32 = SteamPackageArchive.ComputeCrc32(rawZipBytes);
        byte[] output = new byte[12 + lzmaPayload.Length + 10];
        output[0] = (byte)'V';
        output[1] = (byte)'Z';
        // bytes [2..7] 为 5 字节 VZ 头部元数据占位
        props.CopyTo(output, 7);
        lzmaPayload.CopyTo(output, 12);
        int trailerOffset = 12 + lzmaPayload.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(trailerOffset, 4), crc32);
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(trailerOffset + 4, 4), (uint)rawZipBytes.Length);
        output[trailerOffset + 8] = (byte)'z';
        output[trailerOffset + 9] = (byte)'v';
        return output;
    }

    private static async Task<bool> ThrowsInvalidAsync(Func<Task> action)
    {
        try
        {
            await action().ConfigureAwait(false);
            return false;
        }
        catch (Exception ex) when (ex is InvalidDataException or UnauthorizedAccessException)
        {
            return true;
        }
    }

    private sealed class PackageMockCdnHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }

    private sealed class PackageRepeatedByteStream(long length) : Stream
    {
        private long _position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int toRead = (int)Math.Min(count, length - _position);
            if (toRead <= 0) return 0;
            Array.Clear(buffer, offset, toRead);
            _position += toRead;
            return toRead;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

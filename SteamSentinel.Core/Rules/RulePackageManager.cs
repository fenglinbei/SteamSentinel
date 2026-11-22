using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Reporting;
using SteamSentinel.Core.Steam;

namespace SteamSentinel.Core.Rules;

/// <summary>
/// 本地离线签名规则包管理器。仅信任内置发布者 RSA 公钥，使用 RSA-PSS/SHA-256 验签，
/// 校验有效期与版本号后采用跨进程锁原子替换，且只允许增量追加规则，不可改写或删除既有规则。
/// </summary>
public static class RulePackageManager
{
    public const string SigningKeyId = "3395882D18D66EFA1545C1FE6DD867EB004176D1";
    public const int MaximumPackageBytes = 4 * 1024 * 1024;
    public const int MaximumPayloadBytes = 3 * 1024 * 1024;
    public const string SourceBuiltIn = "BuiltIn";
    public const string SourceSignedPackage = "SignedPackage";
    private const string ProductName = "SteamSentinel";
    private static readonly object ImportLock = new();

    private static readonly JsonSerializerOptions PackageJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        MaxDepth = 16,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter() }
    };

    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SteamSentinel",
        "Rules");

    /// <summary>
    /// 加载当前生效规则快照；若本地签名包不存在直接返回内置规则，若本地包验证失败则安全回退内置规则并在 Metadata.Notice 提示。
    /// </summary>
    public static ActiveRuleSnapshot LoadActive(string? directory = null)
    {
        RuleSet builtIn = RuleLoader.LoadEmbedded();
        ActiveRuleSnapshot snapshot = CreateSnapshot(builtIn, SourceBuiltIn);
        string activePath = Path.Combine(directory ?? DefaultDirectory, "active.rules.json");
        try
        {
            // 先区分“文件尚未部署”和“存在但不可读/重定向异常”
            try { _ = File.GetAttributes(activePath); }
            catch (FileNotFoundException) { return snapshot; }
            catch (DirectoryNotFoundException) { return snapshot; }

            using RSA publicKey = PublisherKey();
            RulePackagePayload payload = VerifyPackage(ReadLocalBytes(activePath), publicKey, DateTimeOffset.UtcNow);
            RuleSet merged = MergeWithBuiltIn(builtIn, payload);
            return CreateSnapshot(merged, SourceSignedPackage, versionOverride: payload.Version, publishedOverride: payload.PublishedAtUtc);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or UnauthorizedAccessException
            or CryptographicException or JsonException or ArgumentException or FormatException)
        {
            return snapshot with
            {
                Metadata = snapshot.Metadata with
                {
                    Notice = DisplayText.Get("Rules.Package.LoadFallbackNotice")
                }
            };
        }
    }

    /// <summary>
    /// 验签并原子导入离线规则包，防止版本降级、规则被删改以及多实例并发写入冲突。
    /// </summary>
    public static ActiveRuleSnapshot Import(string packagePath, string? directory = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(packagePath);
        byte[] bytes = ReadLocalBytes(packagePath);
        using RSA publicKey = PublisherKey();
        RulePackagePayload payload = VerifyPackage(bytes, publicKey, DateTimeOffset.UtcNow);
        RuleSet builtIn = RuleLoader.LoadEmbedded();
        RuleSet incoming = MergeWithBuiltIn(builtIn, payload);
        string targetDirectory = Path.GetFullPath(directory ?? DefaultDirectory);

        lock (ImportLock)
        {
            EnsureLocal(targetDirectory);
            Directory.CreateDirectory(targetDirectory);
            EnsureLocal(targetDirectory);
            string lockPath = Path.Combine(targetDirectory, "import.lock");
            EnsureLocal(lockPath);

            using FileStream importLease = new(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            ActiveRuleSnapshot current = LoadActive(targetDirectory);
            ValidateTransition(current, payload.Version, incoming);

            if (CompareRuleVersions(payload.Version, current.Metadata.Version) == 0 &&
                current.Metadata.Notice is null &&
                current.Metadata.Source == SourceSignedPackage)
            {
                return current;
            }

            string activePath = Path.Combine(targetDirectory, "active.rules.json");
            EnsureLocal(activePath);
            string temporaryPath = Path.Combine(targetDirectory, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (FileStream stream = new(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    stream.Write(bytes);
                    stream.Flush(flushToDisk: true);
                }
                EnsureLocal(activePath);
                File.Move(temporaryPath, activePath, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
            }

            return LoadActive(targetDirectory);
        }
    }

    /// <summary>
    /// 仅作为加密签名与数据边界契约的纯验证入口（便于独立测试使用临时 RSA 密钥验证正反用例）。
    /// </summary>
    public static RulePackagePayload VerifyPackage(byte[] bytes, RSA publicKey, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        ArgumentNullException.ThrowIfNull(publicKey);
        if (bytes.Length is 0 or > MaximumPackageBytes)
            throw new InvalidDataException("规则包大小超出限制。");

        RejectDuplicateProperties(bytes);
        RulePackageEnvelope envelope = JsonSerializer.Deserialize<RulePackageEnvelope>(bytes, PackageJsonOptions)
            ?? throw new InvalidDataException("规则包信封为空。");
        if (envelope.SchemaVersion != 1 ||
            !string.Equals(envelope.KeyId, SigningKeyId, StringComparison.Ordinal) ||
            string.IsNullOrEmpty(envelope.PayloadBase64) ||
            string.IsNullOrEmpty(envelope.SignatureBase64))
        {
            throw new InvalidDataException("不支持的规则包格式或签名密钥身份。");
        }

        byte[] payloadBytes = Convert.FromBase64String(envelope.PayloadBase64);
        byte[] signature = Convert.FromBase64String(envelope.SignatureBase64);
        if (payloadBytes.Length is 0 or > MaximumPayloadBytes ||
            signature.Length != publicKey.KeySize / 8 ||
            !publicKey.VerifyData(payloadBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
        {
            throw new InvalidDataException("规则包 RSA-PSS/SHA-256 签名校验失败。");
        }

        RejectDuplicateProperties(payloadBytes);
        RulePackagePayload payload = JsonSerializer.Deserialize<RulePackagePayload>(payloadBytes, PackageJsonOptions)
            ?? throw new InvalidDataException("规则包载荷为空。");

        RuleSet builtIn = RuleLoader.LoadEmbedded();
        Version engineCurrent = ParseEngineVersion(ProductInfo.Version);
        if (payload.SchemaVersion != 1 ||
            !string.Equals(payload.Product, ProductName, StringComparison.Ordinal) ||
            !TryParseRuleVersion(payload.Version, out Version? incomingVersion) ||
            !TryParseRuleVersion(builtIn.Version, out Version? builtInVersion) ||
            incomingVersion < builtInVersion ||
            !Version.TryParse(payload.MinimumEngineVersion, out Version? minimumEngine) ||
            minimumEngine > engineCurrent ||
            payload.PublishedAtUtc > now.AddDays(2) ||
            payload.ExpiresAtUtc <= now ||
            payload.ExpiresAtUtc <= payload.PublishedAtUtc ||
            payload.ExpiresAtUtc - payload.PublishedAtUtc > TimeSpan.FromDays(366))
        {
            throw new InvalidDataException("规则包产品、版本、有效期或最低引擎要求不符合规定。");
        }

        _ = MergeWithBuiltIn(builtIn, payload);
        return payload;
    }

    internal static RuleSet MergeWithBuiltIn(RuleSet builtIn, RulePackagePayload payload)
    {
        ArgumentNullException.ThrowIfNull(builtIn);
        ArgumentNullException.ThrowIfNull(payload);

        List<HashRule> mergedHashes = [.. builtIn.KnownHashes];
        Dictionary<string, HashRule> hashById = mergedHashes.ToDictionary(r => r.Id, StringComparer.OrdinalIgnoreCase);
        Dictionary<string, HashRule> hashByDigest = mergedHashes.ToDictionary(r => r.Sha256, StringComparer.OrdinalIgnoreCase);
        if (payload.KnownHashes is not null)
        {
            foreach (HashRule incoming in payload.KnownHashes)
            {
                if (incoming is null) throw new InvalidDataException("规则包内存在空哈希规则。");
                bool existingId = hashById.TryGetValue(incoming.Id, out HashRule? byIdRule);
                bool existingDigest = hashByDigest.TryGetValue(incoming.Sha256, out HashRule? byDigestRule);
                if (existingId || existingDigest)
                {
                    if (!existingId || !existingDigest || !SameHashRule(byIdRule!, incoming) || !SameHashRule(byDigestRule!, incoming))
                        throw new InvalidDataException($"规则包试图改写或冲突已有哈希规则：{incoming.Id}");
                    continue;
                }
                mergedHashes.Add(incoming);
                hashById.Add(incoming.Id, incoming);
                hashByDigest.Add(incoming.Sha256, incoming);
            }
        }

        List<StringRule> mergedStrings = [.. builtIn.SuspiciousStrings];
        Dictionary<string, StringRule> stringById = mergedStrings.ToDictionary(r => r.Id, StringComparer.OrdinalIgnoreCase);
        if (payload.SuspiciousStrings is not null)
        {
            foreach (StringRule incoming in payload.SuspiciousStrings)
            {
                if (incoming is null) throw new InvalidDataException("规则包内存在空字符串规则。");
                if (stringById.TryGetValue(incoming.Id, out StringRule? existing))
                {
                    if (!SameStringRule(existing, incoming))
                        throw new InvalidDataException($"规则包试图改写已有字符串规则：{incoming.Id}");
                    continue;
                }
                mergedStrings.Add(incoming);
                stringById.Add(incoming.Id, incoming);
            }
        }

        RuleSet merged = new()
        {
            SchemaVersion = builtIn.SchemaVersion,
            Version = payload.Version,
            PublishedAtUtc = payload.PublishedAtUtc,
            KnownHashes = mergedHashes,
            KnownDomains = MergeTextList(builtIn.KnownDomains, payload.KnownDomains),
            KnownProcessNames = MergeTextList(builtIn.KnownProcessNames, payload.KnownProcessNames),
            KnownRunValueNames = MergeTextList(builtIn.KnownRunValueNames, payload.KnownRunValueNames),
            KnownTaskNames = MergeTextList(builtIn.KnownTaskNames, payload.KnownTaskNames),
            KnownPathTemplates = MergeTextList(builtIn.KnownPathTemplates, payload.KnownPathTemplates),
            SuspiciousStrings = mergedStrings,
            SteamInjectionNames = MergeTextList(builtIn.SteamInjectionNames, payload.SteamInjectionNames),
            DangerousExtensions = [.. builtIn.DangerousExtensions],
            ArchiveExtensions = [.. builtIn.ArchiveExtensions]
        };

        RuleLoader.Validate(merged);
        return merged;
    }

    internal static void ValidateTransition(ActiveRuleSnapshot current, string nextVersion, RuleSet next)
    {
        if (CompareRuleVersions(nextVersion, current.Metadata.Version) < 0)
            throw new InvalidDataException("拒绝导入版本号低于当前生效规则的旧规则包。");

        if (!IsSupersetOrEqual(current.Rules, next))
            throw new InvalidDataException("更新规则包不得删除或改写当前已生效的规则。");

        if (CompareRuleVersions(nextVersion, current.Metadata.Version) == 0 && !SameRuleSet(current.Rules, next))
            throw new InvalidDataException("同版本号规则包内容与当前生效规则存在冲突，请使用递增版本号发布。");
    }

    private static ActiveRuleSnapshot CreateSnapshot(RuleSet rules, string source, string? versionOverride = null, DateTimeOffset? publishedOverride = null) =>
        new(rules, new RuleSetMetadata(
            versionOverride ?? rules.Version,
            publishedOverride ?? rules.PublishedAtUtc,
            source,
            rules.KnownHashes.Count,
            rules.KnownDomains.Count));

    private static List<string> MergeTextList(IEnumerable<string> existing, IEnumerable<string>? additions)
    {
        List<string> merged = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        foreach (string item in existing)
            if (seen.Add(item)) merged.Add(item);
        if (additions is not null)
        {
            foreach (string item in additions)
            {
                if (item is null) throw new InvalidDataException("规则包列表内包含空值。");
                if (seen.Add(item)) merged.Add(item);
            }
        }
        return merged;
    }

    private static bool IsSupersetOrEqual(RuleSet baseline, RuleSet candidate)
    {
        Dictionary<string, HashRule> candidateHashes = candidate.KnownHashes.ToDictionary(r => r.Id, StringComparer.OrdinalIgnoreCase);
        foreach (HashRule item in baseline.KnownHashes)
            if (!candidateHashes.TryGetValue(item.Id, out HashRule? found) || !SameHashRule(item, found)) return false;

        Dictionary<string, StringRule> candidateStrings = candidate.SuspiciousStrings.ToDictionary(r => r.Id, StringComparer.OrdinalIgnoreCase);
        foreach (StringRule item in baseline.SuspiciousStrings)
            if (!candidateStrings.TryGetValue(item.Id, out StringRule? found) || !SameStringRule(item, found)) return false;

        return ContainsAll(candidate.KnownDomains, baseline.KnownDomains) &&
               ContainsAll(candidate.KnownProcessNames, baseline.KnownProcessNames) &&
               ContainsAll(candidate.KnownRunValueNames, baseline.KnownRunValueNames) &&
               ContainsAll(candidate.KnownTaskNames, baseline.KnownTaskNames) &&
               ContainsAll(candidate.KnownPathTemplates, baseline.KnownPathTemplates) &&
               ContainsAll(candidate.SteamInjectionNames, baseline.SteamInjectionNames);
    }

    private static bool SameRuleSet(RuleSet first, RuleSet second) =>
        IsSupersetOrEqual(first, second) && IsSupersetOrEqual(second, first);

    private static bool ContainsAll(IEnumerable<string> superset, IEnumerable<string> subset)
    {
        HashSet<string> set = new(superset, StringComparer.OrdinalIgnoreCase);
        return subset.All(set.Contains);
    }

    private static bool SameHashRule(HashRule a, HashRule b) =>
        string.Equals(a.Id, b.Id, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(a.Sha256, b.Sha256, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(a.Label, b.Label, StringComparison.Ordinal) &&
        a.Severity == b.Severity &&
        a.Malware == b.Malware &&
        a.Remediable == b.Remediable &&
        string.Equals(a.Evidence, b.Evidence, StringComparison.Ordinal) &&
        a.LabelMessage == b.LabelMessage &&
        a.EvidenceMessage == b.EvidenceMessage;

    private static bool SameStringRule(StringRule a, StringRule b) =>
        string.Equals(a.Id, b.Id, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(a.Value, b.Value, StringComparison.OrdinalIgnoreCase) &&
        a.Score == b.Score &&
        string.Equals(a.Label, b.Label, StringComparison.Ordinal) &&
        a.LabelMessage == b.LabelMessage;

    private static int CompareRuleVersions(string left, string right)
    {
        if (!TryParseRuleVersion(left, out Version? vLeft) || !TryParseRuleVersion(right, out Version? vRight))
            throw new InvalidDataException("规则版本号格式无效，必须为四段数字格式（例如 2026.11.17.1）。");
        return vLeft.CompareTo(vRight);
    }

    internal static bool TryParseRuleVersion(string? text, out Version version)
    {
        version = new Version(0, 0, 0, 0);
        if (string.IsNullOrWhiteSpace(text)) return false;
        string[] parts = text.Split('.');
        if (parts.Length != 4) return false;
        int[] nums = new int[4];
        for (int i = 0; i < 4; i++)
        {
            if (parts[i].Length == 0 || !parts[i].All(char.IsAsciiDigit) ||
                !int.TryParse(parts[i], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out nums[i]))
                return false;
        }
        version = new Version(nums[0], nums[1], nums[2], nums[3]);
        return true;
    }

    private static Version ParseEngineVersion(string text)
    {
        string normalized = string.IsNullOrWhiteSpace(text) ? "0.0.0" : text.Split('-')[0];
        return Version.TryParse(normalized, out Version? parsed) ? parsed : new Version(0, 0, 0);
    }

    private static RSA PublisherKey()
    {
        using Stream source = typeof(RulePackageManager).Assembly
            .GetManifestResourceStream("SteamSentinel.Core.Rules.rule-signing.cer")
            ?? throw new CryptographicException("未找到内置规则签名公钥证书。");
        using MemoryStream buffer = new();
        source.CopyTo(buffer);
        using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(buffer.ToArray());
        if (!string.Equals(certificate.Thumbprint, SigningKeyId, StringComparison.Ordinal))
            throw new CryptographicException("内置规则签名信任身份校验不一致。");
        return certificate.GetRSAPublicKey() ?? throw new CryptographicException("内置规则签名公钥不可用。");
    }

    private static byte[] ReadLocalBytes(string path)
    {
        EnsureLocal(path);
        using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length is 0 or > MaximumPackageBytes)
            throw new InvalidDataException("规则包大小不符合限制。");
        byte[] bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return bytes;
    }

    private static void EnsureLocal(string path)
    {
        if (!ContentDiscovery.IsLocalSafePath(Path.GetFullPath(path)))
            throw new IOException("规则文件必须位于可安全读取的本地目录，不支持网络路径或重解析点。");
    }

    private static void RejectDuplicateProperties(byte[] bytes)
    {
        using JsonDocument document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
        Walk(document.RootElement);

        static void Walk(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                HashSet<string> names = new(StringComparer.Ordinal);
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    if (!names.Add(property.Name))
                        throw new InvalidDataException("规则包包含重复 JSON 属性字段。");
                    Walk(property.Value);
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement child in element.EnumerateArray()) Walk(child);
            }
        }
    }
}

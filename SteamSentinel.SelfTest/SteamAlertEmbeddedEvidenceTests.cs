using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Reflection.Emit;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32;
using SteamSentinel.Broker;
using SteamSentinel.Core.Inspection;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Remediation;
using SteamSentinel.Core.Scanning;
using SteamSentinel.Core.Steam;
using SteamSentinel.Core.Utilities;

namespace SteamSentinel.SelfTest;

internal static partial class Program
{
    private static async Task TestSteamAlertEmbeddedEvidenceAsync(string root)
    {
        // These PEs are metadata-only fixtures with throwing type initializers. Never load or execute them.
        byte[] core = EmbeddedCoreFixture();
        string coreHash = Hashing.Sha256Bytes(core);
        RuleSet rules = new() { KnownHashes = [new() { Id = "STEAMALERT-CORE", Sha256 = coreHash, Malware = true, Severity = FindingSeverity.Critical }] };
        SteamAlertEmbeddedProof? Inspect(byte[] bytes, RuleSet? ruleSet = null)
        {
            using MemoryStream stream = new(bytes);
            return SteamAlertEmbeddedEvidence.Inspect(stream, ruleSet ?? rules);
        }
        foreach (EmbeddedHostCase mode in new[] { EmbeddedHostCase.Valid, EmbeddedHostCase.TypeHandle, EmbeddedHostCase.Finally })
        {
            SteamAlertEmbeddedProof? proof = Inspect(EmbeddedHostFixture(core, mode));
            Check("Embedded Core: follows real resource-to-invocation data flow " + mode,
                proof is { RuleId: SteamAlertEmbeddedEvidence.RuleId, ResourceName: "renamed.payload" } && proof.PayloadSha256 == coreHash);
        }
        foreach (EmbeddedHostCase mode in Enum.GetValues<EmbeddedHostCase>().Except([EmbeddedHostCase.Valid, EmbeddedHostCase.TypeHandle, EmbeddedHostCase.Finally]))
            Check("Embedded Core: refuses disconnected or modified binding " + mode, Inspect(EmbeddedHostFixture(core, mode)) is null);
        Check("Embedded Core: old behavior-only cooccurrence fixture is not proof", Inspect(HostFixture("renamed.payload", core)) is null);
        Check("Embedded Core: an unknown payload never becomes confirmed", Inspect(EmbeddedHostFixture(EmbeddedCoreFixture())) is null);
        Check("Embedded Core: benign hash classification cannot authorize a host", Inspect(EmbeddedHostFixture(core),
            new RuleSet { KnownHashes = [new() { Id = "STEAMALERT-CORE", Sha256 = coreHash, Malware = false }] }) is null);
        Check("Embedded Core: an unrelated known-hash rule cannot authorize a host", Inspect(EmbeddedHostFixture(core),
            new RuleSet { KnownHashes = [new() { Id = "OTHER-FAMILY", Sha256 = coreHash, Malware = true }] }) is null);
        byte[] incompatibleCore = InnerFixture(true, true);
        Check("Embedded Core: requires the core's unambiguous public Run(string)", Inspect(EmbeddedHostFixture(incompatibleCore),
            new RuleSet { KnownHashes = [new() { Id = "STEAMALERT-CORE", Sha256 = Hashing.Sha256Bytes(incompatibleCore), Malware = true }] }) is null);
        byte[] host = EmbeddedHostFixture(core);
        Check("Embedded Core: rejects truncated and oversized images", Inspect(host[..128]) is null &&
            Inspect(new byte[checked((int)SteamAlertEmbeddedEvidence.MaximumBytes + 1)]) is null);
        using (MemoryStream positioned = new(host))
        {
            positioned.Position = 19;
            bool found = SteamAlertEmbeddedEvidence.Inspect(positioned, rules) is not null;
            Check("Embedded Core: preserves the caller's stream position", found && positioned.Position == 19);
            bool cancelled = false;
            try { SteamAlertEmbeddedEvidence.Inspect(positioned, rules, new CancellationToken(true)); }
            catch (OperationCanceledException) { cancelled = true; }
            Check("Embedded Core: cancellation propagates and preserves position", cancelled && positioned.Position == 19);
        }

        string directory = Path.Combine(root, "embedded-core-" + Guid.NewGuid().ToString("N"));
        string resident = Path.Combine(directory, "profile", "SteamAlertDemo"), downloads = Path.Combine(directory, "Downloads");
        Directory.CreateDirectory(resident); Directory.CreateDirectory(downloads);
        string path = Path.Combine(resident, "Application Frame Host.exe"), copy = Path.Combine(downloads, "evidence.exe");
        await File.WriteAllBytesAsync(path, host); File.Copy(path, copy);
        string hostHash = Hashing.Sha256Bytes(host);
        string zip = Path.Combine(directory, "fixture.zip");
        using (ZipArchive archive = ZipFile.Open(zip, ZipArchiveMode.Create))
        using (Stream member = archive.CreateEntry("member.exe").Open()) member.Write(host);
        ScanReport scan = await new ScanCoordinator(rules, new SteamLayout()).RunAsync(new ScanOptions
        {
            Mode = ScanMode.Custom, IncludeSystem = false, IncludeSteam = false, IncludeWorkshop = false,
            UseAmsi = false, InspectArchives = true, InspectDeepSignatures = false, CustomRoots = [directory]
        });
        Finding[] foundHosts = scan.Findings.Where(f => f.RuleId == SteamAlertEmbeddedEvidence.RuleId).ToArray();
        Check("Embedded Core: loose hosts and archive members retain their distinct identities",
            foundHosts.Any(f => f.Target == path && f.Sha256 == hostHash && f.TargetSha256 == hostHash) &&
            foundHosts.Any(f => f.Target == zip && f.Sha256 == hostHash && f.TargetSha256 != hostHash));
        Check("Embedded Core: confirmation does not pretend the whole host hash is known",
            foundHosts.Length == 3 && foundHosts.All(f => f is { IsKnownMalware: false, Score: 100 } &&
                f.ReasonCode == SteamAlertEmbeddedEvidence.ReasonCode) &&
            foundHosts.Where(f => f.Target != zip).All(f => f.CanRemediate && f.SuggestedActions.SequenceEqual([SuggestedActionKind.QuarantineFile])));
        Check("Embedded Core: unimplemented outer-archive proof remains review-only",
            foundHosts.FirstOrDefault(f => f.Target == zip) is { CanRemediate: false } packed && packed.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
        Check("Embedded Core: Broker verifier uses embedded production rules, not a report's synthetic allowlist",
            await BoundContentEvidence.VerifyAsync(path, hostHash) is null);

        Finding Source(string source, string? expected = null) => new()
        {
            RuleId = SteamAlertEmbeddedEvidence.RuleId, ReasonCode = SteamAlertEmbeddedEvidence.ReasonCode,
            Category = FindingCategory.File, Target = source, ContentPath = source,
            Sha256 = expected ?? hostHash, TargetSha256 = expected ?? hostHash,
            CanRemediate = true, Score = 100, Severity = FindingSeverity.Critical,
            SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        RelatedArtifactScanner related = new(rules);
        Finding? verified = related.RegisterVerifiedFileFinding(path, hostHash, Source(path));
        Check("Embedded Core: association independently rechecks the physical host bytes", verified is { CanRemediate: true, IsKnownMalware: false });
        Check("Embedded Core: installed location is required for entry closure",
            verified is not null && RelatedArtifactRelations.SupportsBoundEntry(verified, resident) && !RelatedArtifactRelations.SupportsBoundEntry(Source(copy), resident));
        Check("Embedded Core: only direct commands bind to a host",
            BoundContentEvidence.IsDirectInvocation('"' + path + '"', path) &&
            !BoundContentEvidence.IsDirectInvocation("cmd.exe /c echo " + '"' + path + '"', path) &&
            !BoundContentEvidence.IsDirectInvocation('"' + copy + '"', path));
        Finding? direct = related.CreateProcessAssociation(path, hostHash, path, hostHash, 54321, DateTimeOffset.UnixEpoch, resident);
        Finding? loaded = related.CreateProcessAssociation(copy, hostHash, path, hostHash, 54322, DateTimeOffset.UnixEpoch, resident);
        Check("Embedded Core: confirmed direct image may stop, unrelated loading host remains review-only",
            direct is { CanRemediate: true, IsKnownMalware: false, ReasonCode: SteamAlertEmbeddedEvidence.ReasonCode } &&
            loaded is { CanRemediate: false, IsKnownMalware: false } && loaded.SuggestedActions.SequenceEqual([SuggestedActionKind.ReviewOnly]));
        related.RegisterVerifiedFileFinding(copy, hostHash, Source(copy));
        Check("Embedded Core: an evidence copy cannot authorize stopping a process",
            related.CreateProcessAssociation(copy, hostHash, copy, hostHash, 54323, DateTimeOffset.UnixEpoch, resident) is { CanRemediate: false });
        Check("Embedded Core: changed or fabricated source identity is refused",
            related.RegisterVerifiedFileFinding(path, new string('A', 64), Source(path, new string('A', 64))) is null);

        string mods = Path.Combine(directory, "game", "Mods"), loaderPath = Path.Combine(mods, "3835179592", "PWLoader.dll");
        Directory.CreateDirectory(Path.GetDirectoryName(loaderPath)!);
        await File.WriteAllTextAsync(loaderPath, "inert exact-hash loader fixture; never executed");
        string loaderHash = await Hashing.Sha256FileAsync(loaderPath);
        rules.KnownHashes.Add(new() { Id = SteamAlertInstallation.LoaderRule, Sha256 = loaderHash, Malware = true });
        SteamLayout layout = new(); layout.ContentRoots.Add(new(mods, "1234", "mod", "Test"));
        Finding loaderFinding = new()
        {
            RuleId = SteamAlertInstallation.LoaderRule, Category = FindingCategory.File, Target = loaderPath,
            ContentPath = loaderPath, Sha256 = loaderHash, TargetSha256 = loaderHash, IsKnownMalware = true,
            CanRemediate = true, Score = 100, SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        async Task<RelatedArtifactExpansion> Expand(Finding selected) => await new RelatedArtifactScanner(rules).ExpandLocalAsync([selected],
            new ScanReport { Findings = [selected] }, default, RelatedArtifactScanner.MaximumVerificationBytes, true, layout, resident);
        Check("Embedded Core: installed loader discovers and verifies a rebuilt resident",
            (await Expand(loaderFinding)).Findings.Any(f => f.Target == path && f.RuleId == SteamAlertEmbeddedEvidence.RuleId && f.CanRemediate));
        Check("Embedded Core: installed confirmed resident closes its exact loader dependency",
            (await Expand(Source(path))).Findings.Any(f => f.Target == loaderPath && f.IsKnownMalware && f.CanRemediate));
        Check("Embedded Core: downloaded evidence does not introduce installation dependencies",
            !(await Expand(Source(copy))).Findings.Any(f => f.Target == loaderPath));
        await File.AppendAllTextAsync(path, "identity changed");
        Check("Embedded Core: stale resident cannot introduce a loader dependency",
            !(await Expand(Source(path))).Findings.Any(f => f.Target == loaderPath));
        await TestEmbeddedBrokerBoundariesAsync(directory, host);
        await TestEmbeddedQuarantineRequestAsync(directory, host);
    }

    private static async Task TestEmbeddedQuarantineRequestAsync(string directory, byte[] inertHost)
    {
        string path = Path.Combine(directory, "quarantine-proof-request.exe");
        await File.WriteAllBytesAsync(path, inertHost);
        string hash = Hashing.Sha256Bytes(inertHost);
        Finding finding = new()
        {
            RuleId = SteamAlertEmbeddedEvidence.RuleId, ReasonCode = SteamAlertEmbeddedEvidence.ReasonCode,
            Category = FindingCategory.File, Target = path, ContentPath = path, Sha256 = hash, TargetSha256 = hash,
            CanRemediate = true, Score = 100, Severity = FindingSeverity.Critical, SuggestedActions = [SuggestedActionKind.QuarantineFile]
        };
        RemediationPlan plan = await new RemediationPlanBuilder(new RuleSet()).BuildAsync([finding], false, requestExplicitFileTargets: true);
        RemediationAction file = plan.Actions.Single();
        Check("Embedded quarantine: plan requests independent evidence and captures the exact object",
            file.ContentEvidenceRuleId == SteamAlertEmbeddedEvidence.RuleId && !file.UserSelectedRisk && !file.IsKnownMalware &&
            FileScopeSafety.IsValidIdentity(file.ExpectedFileIdentity) && FileScopeSafety.IsValidIdentity(file.ExpectedParentIdentity));
        BrokerEngine.ValidateContentEvidenceRequestShape(plan);
        string fingerprint = RemediationPlanIdentity.Fingerprint(plan);
        JsonObject original = JsonSerializer.SerializeToNode(plan, JsonFile.Options)!.AsObject();
        JsonObject removed = original.DeepClone().AsObject();
        removed[nameof(RemediationPlan.Actions)]![0]!.AsObject().Remove(nameof(RemediationAction.ContentEvidenceRuleId));
        RemediationPlan legacy = removed.Deserialize<RemediationPlan>(JsonFile.Options)!;
        Check("Embedded quarantine: the confirmation fingerprint binds the verifier request",
            RemediationPlanIdentity.Fingerprint(legacy) != fingerprint && legacy.Actions[0].ContentEvidenceRuleId is null);
        Check("Embedded quarantine: old actions omit the new optional field",
            !JsonSerializer.Serialize(new RemediationAction(), JsonFile.Options).Contains(nameof(RemediationAction.ContentEvidenceRuleId), StringComparison.Ordinal));
        foreach ((string property, JsonNode? value) in new (string, JsonNode?)[]
        {
            (nameof(RemediationAction.ContentEvidenceRuleId), JsonValue.Create("UNSUPPORTED-PROOF")),
            (nameof(RemediationAction.ContentEvidenceRuleId), JsonValue.Create("")),
            (nameof(RemediationAction.UserSelectedRisk), JsonValue.Create(true)),
            (nameof(RemediationAction.IsKnownMalware), JsonValue.Create(true)),
            (nameof(RemediationAction.ConfidenceScore), JsonValue.Create(99)),
            (nameof(RemediationAction.ExpectedFileIdentity), null)
        })
        {
            JsonObject changed = original.DeepClone().AsObject(); changed[nameof(RemediationPlan.Actions)]![0]![property] = value;
            Check("Embedded quarantine: malformed or conflicting request is refused " + property + "=" + value,
                ScopeRejects(() => BrokerEngine.ValidateContentEvidenceRequestShape(changed.Deserialize<RemediationPlan>(JsonFile.Options)!)));
        }
        async Task<bool> Refused(Func<Task> action)
        {
            try { await action(); return false; }
            catch (InvalidDataException) { return true; }
        }
        // A harmless fixture present only in a test scanner's catalog cannot obtain production Broker authority.
        Check("Embedded quarantine: explicit preparation independently refuses invented production evidence",
            await Refused(async () => { _ = await new BrokerEngine().PrepareForConfirmationAsync(plan); }));
        Check("Embedded quarantine: legacy preparation also verifies actual bytes",
            await Refused(async () => { _ = await new BrokerEngine().PrepareForConfirmationAsync(new() { Actions = [file] }); }));
        await using (SecureFileLease lease = SecureFileLease.Open(path))
            Check("Embedded quarantine: the locked execution gate independently refuses invented evidence",
                await Refused(async () => { _ = await BrokerEngine.VerifyQuarantineContentEvidenceAsync(file, lease, CancellationToken.None); }));
        Check("Embedded quarantine: every failed gate leaves the original bytes intact", await Hashing.Sha256FileAsync(path) == hash);
    }

    private static async Task TestEmbeddedBrokerBoundariesAsync(string directory, byte[] inertHost)
    {
        string resident = Path.Combine(directory, "scope", "SteamAlertDemo"), installed = Path.Combine(resident, "renamed.exe");
        string other = Path.Combine(directory, "Downloads", "renamed.exe"), hash = Hashing.Sha256Bytes(inertHost);
        RemediationAction Action(RemediationActionType type = RemediationActionType.RemoveRegistryValue, string? path = null,
            string hive = "HKCU", string key = @"Software\Microsoft\Windows\CurrentVersion\Run", string? image = null,
            string? imageHash = null, bool known = false, bool risk = false, int score = 100) => new()
        {
            Type = type, Target = image ?? path ?? installed, RelatedFilePath = path ?? installed, RelatedFileSha256 = hash,
            ExpectedSha256 = imageHash ?? hash, ConfidenceScore = score, ProcessId = 54321,
            ProcessStartedAtUtc = DateTimeOffset.UnixEpoch, RegistryHive = hive, RegistryView = "Default",
            RegistryKey = key, RegistryValueName = "inert-fixture", IsKnownMalware = known, UserSelectedRisk = risk
        };
        string command = '"' + installed + '"';
        Check("Embedded Broker: independent proof still needs installed direct Run scope",
            BrokerEngine.SupportsEmbeddedBoundAction(Action(), command, resident));
        Check("Embedded Broker: independent proof still needs the same direct process image",
            BrokerEngine.SupportsEmbeddedBoundAction(Action(RemediationActionType.StopProcess), null, resident));
        Check("Embedded Broker: evidence copies and arbitrary related hosts are excluded",
            !BrokerEngine.SupportsEmbeddedBoundAction(Action(path: other), '"' + other + '"', resident) &&
            !BrokerEngine.SupportsEmbeddedBoundAction(Action(RemediationActionType.StopProcess, image: other), null, resident) &&
            !BrokerEngine.SupportsEmbeddedBoundAction(Action(RemediationActionType.StopProcess, imageHash: new string('B', 64)), null, resident));
        Check("Embedded Broker: HKLM, RunOnce and shell text do not inherit Run permission",
            !BrokerEngine.SupportsEmbeddedBoundAction(Action(hive: "HKLM"), command, resident) &&
            !BrokerEngine.SupportsEmbeddedBoundAction(Action(key: @"Software\Microsoft\Windows\CurrentVersion\RunOnce"), command, resident) &&
            !BrokerEngine.SupportsEmbeddedBoundAction(Action(), "cmd.exe /c echo " + command, resident));
        Check("Embedded Broker: services, tasks and loaded-host termination remain excluded",
            new[] { RemediationActionType.DisableService, RemediationActionType.RemoveScheduledTask, RemediationActionType.StopHostProcess }
                .All(type => !BrokerEngine.SupportsEmbeddedBoundAction(Action(type), command, resident)));
        Check("Embedded Broker: report flags cannot substitute for exact embedded proof",
            !BrokerEngine.SupportsEmbeddedBoundAction(Action(known: true), command, resident) &&
            !BrokerEngine.SupportsEmbeddedBoundAction(Action(risk: true), command, resident) &&
            !BrokerEngine.SupportsEmbeddedBoundAction(Action(score: 99), command, resident));
        QuarantineRecord Record(string path, string? proof = SteamAlertEmbeddedEvidence.RuleId, string hive = "HKCU",
            string key = @"Software\Microsoft\Windows\CurrentVersion\Run", string? saved = null, bool risk = false) => new()
        {
            Type = RemediationActionType.RemoveRegistryValue, OriginalTarget = path, RelatedFilePath = path,
            RelatedFileSha256 = hash, VerifiedContentRuleId = proof, RegistryHive = hive, RegistryView = "Default",
            RegistryKey = key, RegistryValueName = "inert-fixture", RegistryValueData = saved ?? ('"' + path + '"'),
            RegistryValueKind = (int)RegistryValueKind.String, UserSelectedRisk = risk, MutationConfirmed = true
        };
        Check("Embedded Broker: trusted rollback shape preserves exact installed Run binding",
            BrokerEngine.SupportsEmbeddedRegistryRecord(Record(installed), resident));
        Check("Embedded Broker: rollback rejects a moved target, missing proof and changed command",
            !BrokerEngine.SupportsEmbeddedRegistryRecord(Record(other), resident) &&
            !BrokerEngine.SupportsEmbeddedRegistryRecord(Record(installed, proof: null), resident) &&
            !BrokerEngine.SupportsEmbeddedRegistryRecord(Record(installed, saved: "cmd.exe /c echo " + command), resident));
        Check("Embedded Broker: rollback cannot change authority into another registry scope or user risk",
            !BrokerEngine.SupportsEmbeddedRegistryRecord(Record(installed, hive: "HKLM"), resident) &&
            !BrokerEngine.SupportsEmbeddedRegistryRecord(Record(installed, key: @"Software\Microsoft\Windows\CurrentVersion\RunOnce"), resident) &&
            !BrokerEngine.SupportsEmbeddedRegistryRecord(Record(installed, risk: true), resident));

        // Verification only: no registry value is read/written, and no fixture process is started/stopped.
        string absentInstalled = Path.Combine(SteamAlertInstallation.ResidentDirectory, "SteamSentinel-inert-" + Guid.NewGuid().ToString("N") + ".exe");
        string backup = Path.Combine(directory, "inert-quarantine-backup.bin");
        await File.WriteAllBytesAsync(backup, inertHost);
        QuarantineRecord record = Record(absentInstalled);
        QuarantineManifest manifest = new()
        {
            Records = [record, new() { Type = RemediationActionType.QuarantineFile, OriginalTarget = absentInstalled, Sha256 = hash, QuarantinedPath = backup }]
        };
        MethodInfo verify = typeof(BrokerEngine).GetMethod("VerifyRecordedContentAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
        bool rejected = false;
        try { await (Task)verify.Invoke(new BrokerEngine(), [record, manifest, CancellationToken.None])!; }
        catch (Exception error) when (error is InvalidOperationException or UnauthorizedAccessException or InvalidDataException or TargetInvocationException)
        { rejected = true; }
        Check("Embedded Broker: protected record claims still require production-known payload bytes", rejected);
        Check("Embedded Broker: verification leaves the backup bytes unchanged", await Hashing.Sha256FileAsync(backup) == hash);
    }

    private enum EmbeddedHostCase { Valid, TypeHandle, Finally, MissingResource, ForeignAssembly, DeadBranch, DifferentBytes, MutatedBytes, FinallyReplacesBytes, WrongType, WrongMethod, NoInvoke, NullArguments, ConsumedResource, DisposedResource, ReopenedResourceAlias }

    private static byte[] EmbeddedCoreFixture()
    {
        ManagedModFixture fixture = new("inert-core-" + Guid.NewGuid().ToString("N"));
        TypeBuilder type = fixture.DefineGuardedType("SteamAlertCore.Core");
        type.DefineMethod("Run", MethodAttributes.Public | MethodAttributes.Static, typeof(void), [typeof(string)]).GetILGenerator().Emit(OpCodes.Ret);
        type.CreateType(); return fixture.Emit();
    }

    private static byte[] EmbeddedHostFixture(byte[] core, EmbeddedHostCase mode = EmbeddedHostCase.Valid)
    {
        ManagedModFixture fixture = new("inert-host-" + Guid.NewGuid().ToString("N"));
        TypeBuilder type = fixture.DefineGuardedType("RenamedHost");
        MethodBuilder entry = type.DefineMethod("Main", MethodAttributes.Public | MethodAttributes.Static, typeof(void), Type.EmptyTypes);
        ILGenerator il = entry.GetILGenerator();
        LocalBuilder bytes = il.DeclareLocal(typeof(byte[])), input = il.DeclareLocal(typeof(Stream)), output = il.DeclareLocal(typeof(MemoryStream));
        Label done = il.DefineLabel();
        if (mode == EmbeddedHostCase.DeadBranch) { il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Brfalse, done); }
        if (mode == EmbeddedHostCase.TypeHandle)
        {
            il.Emit(OpCodes.Ldtoken, type); il.Emit(OpCodes.Call, typeof(Type).GetMethod("GetTypeFromHandle")!);
            il.Emit(OpCodes.Callvirt, typeof(Type).GetProperty("Assembly")!.GetMethod!);
        }
        else il.Emit(OpCodes.Call, typeof(Assembly).GetMethod(mode == EmbeddedHostCase.ForeignAssembly ? "GetEntryAssembly" : "GetExecutingAssembly")!);
        il.Emit(OpCodes.Ldstr, mode == EmbeddedHostCase.MissingResource ? "missing.payload" : "renamed.payload");
        il.Emit(OpCodes.Callvirt, typeof(Assembly).GetMethod("GetManifestResourceStream", [typeof(string)])!); il.Emit(OpCodes.Stloc, input);
        bool withFinally = mode is EmbeddedHostCase.Finally or EmbeddedHostCase.FinallyReplacesBytes;
        if (withFinally) il.BeginExceptionBlock();
        if (mode is EmbeddedHostCase.DisposedResource or EmbeddedHostCase.ReopenedResourceAlias)
        {
            il.Emit(OpCodes.Ldloc, input); il.Emit(OpCodes.Callvirt, typeof(IDisposable).GetMethod("Dispose")!);
            if (mode == EmbeddedHostCase.ReopenedResourceAlias)
            {
                il.Emit(OpCodes.Call, typeof(Assembly).GetMethod("GetExecutingAssembly")!); il.Emit(OpCodes.Ldstr, "renamed.payload");
                il.Emit(OpCodes.Callvirt, typeof(Assembly).GetMethod("GetManifestResourceStream", [typeof(string)])!); il.Emit(OpCodes.Pop);
            }
        }
        il.Emit(OpCodes.Newobj, typeof(MemoryStream).GetConstructor(Type.EmptyTypes)!); il.Emit(OpCodes.Stloc, output);
        il.Emit(OpCodes.Ldloc, input); il.Emit(OpCodes.Ldloc, output); il.Emit(OpCodes.Callvirt, typeof(Stream).GetMethod("CopyTo", [typeof(Stream)])!);
        if (mode == EmbeddedHostCase.ConsumedResource)
        {
            il.Emit(OpCodes.Newobj, typeof(MemoryStream).GetConstructor(Type.EmptyTypes)!); il.Emit(OpCodes.Stloc, output);
            il.Emit(OpCodes.Ldloc, input); il.Emit(OpCodes.Ldloc, output); il.Emit(OpCodes.Callvirt, typeof(Stream).GetMethod("CopyTo", [typeof(Stream)])!);
        }
        il.Emit(OpCodes.Ldloc, output); il.Emit(OpCodes.Callvirt, typeof(MemoryStream).GetMethod("ToArray")!); il.Emit(OpCodes.Stloc, bytes);
        if (withFinally)
        {
            il.BeginFinallyBlock();
            if (mode == EmbeddedHostCase.FinallyReplacesBytes) { il.Emit(OpCodes.Ldnull); il.Emit(OpCodes.Stloc, bytes); }
            il.Emit(OpCodes.Ldloc, input); il.Emit(OpCodes.Callvirt, typeof(IDisposable).GetMethod("Dispose")!); il.EndExceptionBlock();
        }
        if (mode == EmbeddedHostCase.MutatedBytes)
        { il.Emit(OpCodes.Ldloc, bytes); il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Stelem_I1); }
        if (mode == EmbeddedHostCase.DifferentBytes) il.Emit(OpCodes.Ldnull); else il.Emit(OpCodes.Ldloc, bytes);
        il.Emit(OpCodes.Call, typeof(Assembly).GetMethod("Load", [typeof(byte[])])!);
        il.Emit(OpCodes.Ldstr, mode == EmbeddedHostCase.WrongType ? "Unrelated.Type" : "SteamAlertCore.Core");
        il.Emit(OpCodes.Callvirt, typeof(Assembly).GetMethod("GetType", [typeof(string)])!);
        il.Emit(OpCodes.Ldstr, mode == EmbeddedHostCase.WrongMethod ? "Unused" : "Run");
        il.Emit(OpCodes.Callvirt, typeof(Type).GetMethod("GetMethod", [typeof(string)])!);
        if (mode == EmbeddedHostCase.NoInvoke) il.Emit(OpCodes.Pop);
        else
        {
            il.Emit(OpCodes.Ldnull);
            if (mode == EmbeddedHostCase.NullArguments) il.Emit(OpCodes.Ldnull);
            else
            {
                il.Emit(OpCodes.Ldc_I4_1); il.Emit(OpCodes.Newarr, typeof(object)); il.Emit(OpCodes.Dup);
                il.Emit(OpCodes.Ldc_I4_0); il.Emit(OpCodes.Ldstr, ""); il.Emit(OpCodes.Stelem_Ref);
            }
            il.Emit(OpCodes.Callvirt, typeof(MethodBase).GetMethod("Invoke", [typeof(object), typeof(object[])])!); il.Emit(OpCodes.Pop);
        }
        il.MarkLabel(done); il.Emit(OpCodes.Ret); type.CreateType();
        return fixture.Emit(entry, "renamed.payload", core);
    }
}

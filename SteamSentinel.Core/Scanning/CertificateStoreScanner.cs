using SteamSentinel.Core.Reporting;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using SteamSentinel.Core.Models;

namespace SteamSentinel.Core.Scanning;

/// <summary>
/// Reads public certificate bytes from four physical registry stores, never the
/// CurrentUser logical collection (which also contains LocalMachine entries).
/// No store writes, certificate/private-key imports, or private-key access occur.
/// </summary>
public sealed class CertificateStoreScanner
{
    internal const string PhysicalProvider = "CERT_STORE_PROV_SYSTEM_REGISTRY_W";
    internal const string SnapshotChainScope = "OfflineSnapshot:CustomRootTrust+ExtraStore;NoDownloads;NoRevocation";
    private readonly IPhysicalCertificateStoreReader _reader;
    private readonly Func<string?> _currentUserSid;
    private readonly TimeProvider _time;
    private readonly ICertificateSnapshotChainBuilder _chainBuilder;

    public CertificateStoreScanner() : this(new NativePhysicalCertificateStoreReader(), CurrentUserSid,
        TimeProvider.System, new OfflineCertificateSnapshotChainBuilder())
    { }

    internal CertificateStoreScanner(IPhysicalCertificateStoreReader reader, Func<string?> currentUserSid,
        TimeProvider? timeProvider = null, ICertificateSnapshotChainBuilder? chainBuilder = null)
    {
        _reader = reader;
        _currentUserSid = currentUserSid;
        _time = timeProvider ?? TimeProvider.System;
        _chainBuilder = chainBuilder ?? new OfflineCertificateSnapshotChainBuilder();
    }

    public void Collect(TrustProxyDiagnosticReport diagnostic, DiagnosticScanLimits limits, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(diagnostic);
        ArgumentNullException.ThrowIfNull(limits);
        long started = _time.GetTimestamp();
        DateTimeOffset verificationTime = _time.GetUtcNow();
        List<CertificateStoreObservation> stores = [];
        foreach (string scope in new[] { "CurrentUser", "LocalMachine" })
            foreach (string name in new[] { "Root", "CA" })
            {
                CertificateStoreObservation store = new()
                {
                    Scope = scope,
                    StoreName = name,
                    Provider = PhysicalProvider,
                    UserSid = scope == "CurrentUser" ? diagnostic.TargetUserSid : null,
                    Status = DiagnosticReadStatus.NotChecked,
                    DetailText = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.01")
                };
                stores.Add(store);
                diagnostic.CertificateStores.Add(store);
            }
        List<CollectedCertificate> collected = [];
        try
        {
            token.ThrowIfCancellationRequested();
            if (limits.MaximumCertificatesPerStore < 0 || limits.MaximumCertificateBytes < 0 ||
                limits.MaximumTotalCertificateBytes < 0 || limits.MaximumDuration < TimeSpan.Zero)
            {
                FinishUnread(stores, DiagnosticReadStatus.Failed, MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.02"));
                diagnostic.Checks.Add(new() { NameText = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.03"), Status = DiagnosticReadStatus.Failed, DetailText = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.04") });
                return;
            }
            MessageText? identityFailure = ValidateIdentity(diagnostic.TargetUserSid);
            if (identityFailure is not null)
            {
                FinishUnread(stores, DiagnosticReadStatus.AccessDenied, identityFailure);
                diagnostic.Checks.Add(new() { NameText = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.05"), Status = DiagnosticReadStatus.AccessDenied, DetailText = identityFailure });
                return;
            }
            diagnostic.Checks.Add(new()
            {
                NameText = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.06"),
                Status = DiagnosticReadStatus.Complete,
                DetailText = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.07")
            });
            diagnostic.Checks.Add(new()
            {
                NameText = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.08"),
                Status = DiagnosticReadStatus.Complete,
                Required = false,
                DetailText = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.09")
            });

            long totalBytes = 0;
            bool totalLimitReached = false;
            bool Expired() => _time.GetElapsedTime(started) >= limits.MaximumDuration;
            foreach (CertificateStoreObservation store in stores)
            {
                token.ThrowIfCancellationRequested();
                MessageText? currentIdentityFailure = ValidateIdentity(diagnostic.TargetUserSid);
                if (currentIdentityFailure is not null)
                {
                    FinishUnread(stores, DiagnosticReadStatus.AccessDenied, currentIdentityFailure);
                    diagnostic.Checks.Add(new()
                    {
                        NameText = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.10"),
                        Status = DiagnosticReadStatus.AccessDenied,
                        DetailText = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.11") + currentIdentityFailure
                    });
                    break;
                }
                if (Expired() || totalLimitReached || limits.MaximumCertificatesPerStore == 0 ||
                    limits.MaximumCertificateBytes == 0 || limits.MaximumTotalCertificateBytes == 0)
                {
                    store.Status = DiagnosticReadStatus.LimitReached;
                    store.DetailText += MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.12");
                    continue;
                }
                int visited = 0, malformed = 0;
                MessageText? localLimit = null;
                try
                {
                    CertificateStoreReadResult read = _reader.Read(new(store.Scope, store.StoreName, store.UserSid),
                        encodedBytes =>
                        {
                            token.ThrowIfCancellationRequested();
                            if (Expired()) localLimit = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.13");
                            else if (visited >= limits.MaximumCertificatesPerStore) localLimit = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.14");
                            else if (encodedBytes > limits.MaximumCertificateBytes) localLimit = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.15");
                            else if (encodedBytes > limits.MaximumTotalCertificateBytes - totalBytes)
                            { totalLimitReached = true; localLimit = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.16"); }
                            if (localLimit is not null) return false;
                            if (encodedBytes <= 0) throw MessageExceptions.Create(MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.17"), sourceText => new InvalidDataException(sourceText));
                            visited++;
                            totalBytes += encodedBytes;
                            return true;
                        }, der =>
                        {
                            token.ThrowIfCancellationRequested();
                            X509Certificate2? certificate = null;
                            try
                            {
                                // LoadCertificate accepts public certificates only, unlike a PKCS#12 loader.
                                certificate = X509CertificateLoader.LoadCertificate(der);
                                CertificateObservation observation = Describe(certificate, der, store.Id);
                                diagnostic.Certificates.Add(observation);
                                collected.Add(new(certificate, observation, store.StoreName));
                                certificate = null; // Ownership is held until all snapshot chains are checked.
                                store.CertificatesRead++;
                            }
                            catch (Exception ex) when (ex is CryptographicException or ArgumentException or InvalidDataException)
                            { malformed++; }
                            finally { certificate?.Dispose(); }
                        }, token);
                    store.Status = localLimit is not null ? DiagnosticReadStatus.LimitReached : malformed > 0 ? DiagnosticReadStatus.Failed : read.Status;
                    store.DetailText += " " + read.DetailText;
                    if (localLimit is not null) store.DetailText += " " + localLimit;
                    if (malformed > 0) store.DetailText += MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.18", (malformed));
                    if (Expired() && store.Status == DiagnosticReadStatus.Complete)
                    { store.Status = DiagnosticReadStatus.LimitReached; store.DetailText += MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.19"); }
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException)
                { store.Status = DiagnosticReadStatus.AccessDenied; store.DetailText += MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.20") + MessageExceptions.Describe(ex); }
                catch (Exception ex) when (ex is Win32Exception or CryptographicException or IOException or ArgumentException or NotSupportedException)
                { store.Status = DiagnosticReadStatus.Failed; store.DetailText += MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.21") + MessageExceptions.Describe(ex); }
            }
            VerifySnapshotChains(collected, limits, started, verificationTime, token);
        }
        catch (OperationCanceledException)
        {
            FinishUnread(stores, DiagnosticReadStatus.Cancelled, MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.22"));
            foreach (CollectedCertificate item in collected.Where(c => c.Observation.ChainStatus == DiagnosticReadStatus.NotChecked))
            {
                item.Observation.ChainStatus = DiagnosticReadStatus.Cancelled;
                item.Observation.ChainDetailText = MessageText.Create("Backend.Core.CertificateStoreScanner.Collect.23");
            }
            throw;
        }
        finally
        {
            foreach (CollectedCertificate item in collected) item.Certificate.Dispose();
        }
    }

    private MessageText? ValidateIdentity(string targetSid)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(targetSid)) return MessageText.Create("Backend.Core.CertificateStoreScanner.ValidateIdentity.01");
            SecurityIdentifier target = new(targetSid);
            string? effectiveValue = _currentUserSid();
            if (string.IsNullOrWhiteSpace(effectiveValue)) return MessageText.Create("Backend.Core.CertificateStoreScanner.ValidateIdentity.02");
            SecurityIdentifier effective = new(effectiveValue);
            return target.Equals(effective) ? null : MessageText.Create("Backend.Core.CertificateStoreScanner.ValidateIdentity.03");
        }
        catch (Exception ex) when (ex is ArgumentException or UnauthorizedAccessException or System.Security.SecurityException or Win32Exception)
        { return MessageText.Create("Backend.Core.CertificateStoreScanner.ValidateIdentity.04") + MessageExceptions.Describe(ex); }
    }

    private static string? CurrentUserSid()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return identity.User?.Value;
    }

    private static CertificateObservation Describe(X509Certificate2 certificate, byte[] der, string storeId)
    {
        X509BasicConstraintsExtension? basic = null;
        X509KeyUsageExtension? usage = null;
        List<string> ekus = [];
        foreach (X509Extension extension in certificate.Extensions)
        {
            if (extension.Oid?.Value == "2.5.29.19")
            { basic = new(); basic.CopyFrom(extension); }
            else if (extension.Oid?.Value == "2.5.29.15")
            { usage = new(); usage.CopyFrom(extension); }
            else if (extension.Oid?.Value == "2.5.29.37")
            {
                X509EnhancedKeyUsageExtension enhanced = new(); enhanced.CopyFrom(extension);
                ekus.AddRange(enhanced.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value ?? ""));
            }
        }
        return new()
        {
            StoreObservationId = storeId,
            DerSha256 = Convert.ToHexString(SHA256.HashData(der)),
            Sha1Thumbprint = Convert.ToHexString(SHA1.HashData(der)),
            DerBase64 = Convert.ToBase64String(der),
            Subject = certificate.Subject,
            Issuer = certificate.Issuer,
            NotBeforeUtc = certificate.NotBefore.ToUniversalTime(),
            NotAfterUtc = certificate.NotAfter.ToUniversalTime(),
            SubjectEqualsIssuer = certificate.SubjectName.RawData.AsSpan().SequenceEqual(certificate.IssuerName.RawData),
            SelfSignatureVerified = null,
            IsCertificateAuthority = basic?.CertificateAuthority,
            HasPathLengthConstraint = basic?.HasPathLengthConstraint,
            PathLengthConstraint = basic?.HasPathLengthConstraint == true ? basic.PathLengthConstraint : null,
            BasicConstraintsCritical = basic?.Critical,
            KeyUsage = usage?.KeyUsages.ToString(),
            EnhancedKeyUsages = ekus.Distinct(StringComparer.Ordinal).ToList(),
            ChainScope = SnapshotChainScope,
            ChainDetailText = MessageText.Create("Backend.Core.CertificateStoreScanner.Describe.01")
        };
    }

    private void VerifySnapshotChains(List<CollectedCertificate> collected, DiagnosticScanLimits limits,
        long started, DateTimeOffset verificationTime, CancellationToken token)
    {
        List<X509Certificate2> roots = collected.Where(c => c.StoreName == "Root")
            .DistinctBy(c => c.Observation.DerSha256).Select(c => c.Certificate).ToList();
        List<X509Certificate2> extras = collected.Where(c => c.StoreName == "CA")
            .DistinctBy(c => c.Observation.DerSha256).Select(c => c.Certificate).ToList();
        HashSet<string> capturedHashes = collected.Select(c => c.Observation.DerSha256).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, CertificateSnapshotChainResult> cache = new(StringComparer.OrdinalIgnoreCase);
        foreach (CollectedCertificate item in collected)
        {
            token.ThrowIfCancellationRequested();
            CertificateObservation observation = item.Observation;
            if (_time.GetElapsedTime(started) >= limits.MaximumDuration)
            {
                observation.ChainStatus = DiagnosticReadStatus.LimitReached;
                observation.ChainDetailText = MessageText.Create("Backend.Core.CertificateStoreScanner.VerifySnapshotChains.01");
                continue;
            }
            try
            {
                if (!cache.TryGetValue(observation.DerSha256, out CertificateSnapshotChainResult? result))
                {
                    result = _chainBuilder.Build(item.Certificate, roots, extras, verificationTime);
                    cache.Add(observation.DerSha256, result);
                }
                if (_time.GetElapsedTime(started) >= limits.MaximumDuration)
                {
                    observation.ChainStatus = DiagnosticReadStatus.LimitReached;
                    observation.ChainDetailText = MessageText.Create("Backend.Core.CertificateStoreScanner.VerifySnapshotChains.02");
                    continue;
                }
                // Windows may consider cached intermediates even with CustomRootTrust.
                // Never report a snapshot result that used any uncaptured certificate.
                if (result.CertificateHashes.Any(hash => !capturedHashes.Contains(hash)))
                {
                    observation.ChainStatus = DiagnosticReadStatus.NotChecked;
                    observation.ChainFlags.Add("OutsideCapturedSnapshot");
                    observation.ChainDetailText = MessageText.Create("Backend.Core.CertificateStoreScanner.VerifySnapshotChains.03");
                    continue;
                }
                observation.ChainStatus = DiagnosticReadStatus.Complete;
                observation.ChainFlags.AddRange(result.Flags);
                observation.ChainCertificateSha256.AddRange(result.CertificateHashes);
                observation.ChainDetailText = (result.Valid ? MessageText.Create("Backend.Core.CertificateStoreScanner.VerifySnapshotChains.04") : MessageText.Create("Backend.Core.CertificateStoreScanner.VerifySnapshotChains.05")) +
                    MessageText.Create("Backend.Core.CertificateStoreScanner.VerifySnapshotChains.06") +
                    (roots.Count == 0 ? MessageText.Create("Backend.Core.CertificateStoreScanner.VerifySnapshotChains.07") : (MessageText)"") +
                    MessageText.Create("Backend.Core.CertificateStoreScanner.VerifySnapshotChains.08");
            }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException or NotSupportedException)
            {
                observation.ChainStatus = DiagnosticReadStatus.Failed;
                observation.ChainDetailText = MessageText.Create("Backend.Core.CertificateStoreScanner.VerifySnapshotChains.09") + MessageExceptions.Describe(ex);
            }
        }
    }

    private static void FinishUnread(IEnumerable<CertificateStoreObservation> stores, DiagnosticReadStatus status, MessageText detail)
    {
        foreach (CertificateStoreObservation store in stores.Where(s => s.Status == DiagnosticReadStatus.NotChecked))
        { store.Status = status; store.DetailText += " " + detail; }
    }

    private sealed record CollectedCertificate(X509Certificate2 Certificate, CertificateObservation Observation, string StoreName);
}

internal sealed record PhysicalCertificateStoreRequest(string Scope, string StoreName, string? UserSid);
[method: System.Text.Json.Serialization.JsonConstructor]
internal sealed record CertificateStoreReadResult(DiagnosticReadStatus Status, string Detail)
{
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public SteamSentinel.Core.Models.DisplayMessage? DetailMessage { get => SteamSentinel.Core.Reporting.MessageText.BoundDescriptor(field, Detail); init => field = value; }

    [System.Text.Json.Serialization.JsonIgnore]
    public SteamSentinel.Core.Reporting.MessageText DetailText
    {
        get => new(Detail ?? string.Empty, DetailMessage);
        init
        {
            Detail = value.OriginalText;
            DetailMessage = value.Message;
        }
    }

    public CertificateStoreReadResult(DiagnosticReadStatus Status, SteamSentinel.Core.Reporting.MessageText Detail) : this(Status, Detail.OriginalText)
    {
        DetailMessage = Detail.Message;
    }
}
internal interface IPhysicalCertificateStoreReader
{
    CertificateStoreReadResult Read(PhysicalCertificateStoreRequest store, Func<int, bool> reserveBytes,
        Action<byte[]> acceptCertificate, CancellationToken token);
}

internal sealed record CertificateSnapshotChainResult(bool Valid, IReadOnlyList<string> Flags, IReadOnlyList<string> CertificateHashes);
internal interface ICertificateSnapshotChainBuilder
{
    CertificateSnapshotChainResult Build(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> roots,
        IReadOnlyList<X509Certificate2> intermediates, DateTimeOffset verificationTime);
}

internal sealed class OfflineCertificateSnapshotChainBuilder : ICertificateSnapshotChainBuilder
{
    internal static X509ChainPolicy CreatePolicy(IEnumerable<X509Certificate2> roots,
        IEnumerable<X509Certificate2> intermediates, DateTimeOffset verificationTime)
    {
        X509ChainPolicy policy = new()
        {
            TrustMode = X509ChainTrustMode.CustomRootTrust,
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
            VerificationFlags = X509VerificationFlags.NoFlag,
            VerificationTime = verificationTime.UtcDateTime,
            UrlRetrievalTimeout = TimeSpan.FromMilliseconds(1)
        };
        policy.CustomTrustStore.AddRange(roots.ToArray());
        policy.ExtraStore.AddRange(intermediates.ToArray());
        return policy;
    }

    public CertificateSnapshotChainResult Build(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> roots,
        IReadOnlyList<X509Certificate2> intermediates, DateTimeOffset verificationTime)
    {
        using X509Chain chain = new();
        chain.ChainPolicy = CreatePolicy(roots, intermediates, verificationTime);
        bool valid = chain.Build(certificate);
        return new(valid, chain.ChainStatus.Select(s => s.Status.ToString()).ToArray(),
            chain.ChainElements.Cast<X509ChainElement>().Select(e => Convert.ToHexString(SHA256.HashData(e.Certificate.RawData))).ToArray());
    }
}

internal sealed class NativePhysicalCertificateStoreReader : IPhysicalCertificateStoreReader
{
    // Provider documentation: https://learn.microsoft.com/windows/win32/api/wincrypt/nf-wincrypt-certopenstore
    internal const uint ReadOnly = 0x00008000, OpenExisting = 0x00004000, EnumArchived = 0x00000200;
    internal const uint UnprotectedRootEnumeration = 0x40000000;
    internal static uint FlagsFor(PhysicalCertificateStoreRequest store) =>
        ReadOnly | OpenExisting | EnumArchived | (store.Scope == "CurrentUser" ? 0x00010000u : 0x00020000u) |
        (store.Scope == "CurrentUser" && store.StoreName == "Root" ? UnprotectedRootEnumeration : 0);

    public CertificateStoreReadResult Read(PhysicalCertificateStoreRequest store, Func<int, bool> reserveBytes,
        Action<byte[]> acceptCertificate, CancellationToken token)
    {
        if (store.Scope is not ("CurrentUser" or "LocalMachine") || store.StoreName is not ("Root" or "CA"))
            throw MessageExceptions.Create(MessageText.Create("Backend.Core.CertificateStoreScanner.Read.01"), sourceText => new ArgumentException(sourceText));
        token.ThrowIfCancellationRequested();
        using SafeCertificateStoreHandle handle = CertOpenStore(new IntPtr(13), 0, IntPtr.Zero, FlagsFor(store), store.StoreName);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            DiagnosticReadStatus status = error is 5 or unchecked((int)0x80070005) ? DiagnosticReadStatus.AccessDenied :
                error is 2 or 3 or unchecked((int)0x80092004) ? DiagnosticReadStatus.NotPresent : DiagnosticReadStatus.Failed;
            return new(status, MessageText.Create("Backend.Core.CertificateStoreScanner.Read.02", (System.FormattableString.Invariant($"{error:X8}"))));
        }
        IntPtr context = IntPtr.Zero;
        try
        {
            while (true)
            {
                token.ThrowIfCancellationRequested();
                // CertEnumCertificatesInStore releases the previous context, including on failure.
                IntPtr previous = context;
                context = IntPtr.Zero;
                context = CertEnumCertificatesInStore(handle, previous);
                if (context == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    return error == unchecked((int)0x80092004) ? new(DiagnosticReadStatus.Complete, MessageText.Create("Backend.Core.CertificateStoreScanner.Read.03")) :
                        new(DiagnosticReadStatus.Failed, MessageText.Create("Backend.Core.CertificateStoreScanner.Read.04", (System.FormattableString.Invariant($"{error:X8}"))));
                }
                NativeCertificateContext certificate = Marshal.PtrToStructure<NativeCertificateContext>(context);
                if (certificate.EncodedBytes > int.MaxValue) throw MessageExceptions.Create(MessageText.Create("Backend.Core.CertificateStoreScanner.Read.05"), sourceText => new InvalidDataException(sourceText));
                int size = checked((int)certificate.EncodedBytes);
                if (!reserveBytes(size)) return new(DiagnosticReadStatus.LimitReached, MessageText.Create("Backend.Core.CertificateStoreScanner.Read.06"));
                if (certificate.Encoded == IntPtr.Zero) throw MessageExceptions.Create(MessageText.Create("Backend.Core.CertificateStoreScanner.Read.07"), sourceText => new InvalidDataException(sourceText));
                byte[] der = new byte[size];
                Marshal.Copy(certificate.Encoded, der, 0, size);
                acceptCertificate(der);
            }
        }
        finally { if (context != IntPtr.Zero) CertFreeCertificateContext(context); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeCertificateContext
    {
        public uint Encoding;
        public IntPtr Encoded;
        public uint EncodedBytes;
        public IntPtr CertificateInfo;
        public IntPtr Store;
    }

    private sealed class SafeCertificateStoreHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeCertificateStoreHandle() : base(true) { }
        protected override bool ReleaseHandle() => CertCloseStore(handle, 0);
    }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeCertificateStoreHandle CertOpenStore(IntPtr provider, uint encoding, IntPtr cryptProvider, uint flags, string storeName);
    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CertEnumCertificatesInStore(SafeCertificateStoreHandle store, IntPtr previous);
    [DllImport("crypt32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertFreeCertificateContext(IntPtr context);
    [DllImport("crypt32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertCloseStore(IntPtr store, uint flags);
}

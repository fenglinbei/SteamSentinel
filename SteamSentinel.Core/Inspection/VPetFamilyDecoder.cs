using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SteamSentinel.Core.Models;
using SteamSentinel.Core.Scanning;

namespace SteamSentinel.Core.Inspection;

internal sealed class VPetFamilyResult(VPetFamilyEvidence evidence, byte[]? decoded = null) : IDisposable
{
    internal VPetFamilyEvidence Evidence { get; } = evidence;
    internal byte[]? Decoded { get; } = decoded;
    public void Dispose() { if (Decoded is not null) CryptographicOperations.ZeroMemory(Decoded); }
}

/// <summary>Only the observed PX file envelope. Pure bounded byte reconstruction; no native or managed sample execution.</summary>
internal static class VPetFamilyDecoder
{
    internal const int MaximumInputBytes = 8 * 1024 * 1024;
    internal const int MaximumTransformedBytes = 4 * 1024 * 1024;
    private static readonly Dictionary<string, VPetComponentRole> CodeIdentities = new(StringComparer.OrdinalIgnoreCase)
    {
        ["61608a0e5368edb561de5bd8bf4d45dcf88e73368983e8ee00c9644a2214c41c"] = VPetComponentRole.Loader,
        ["ff54c00da7852f2f3c3ef00c2a3ac081a8e000ddbab47f4508b421e415689309"] = VPetComponentRole.UiPayload,
        ["49e73cfa1d40dc1e79ebd9822f43decf4884145eb5caabe040a53dcb4649b018"] = VPetComponentRole.CredentialPayload
    };

    internal static async Task<VPetFamilyResult?> InspectAsync(Stream input, string sourceHash, CancellationToken token,
        ContainerResourceBudget? budget = null, long maximumBytes = MaximumInputBytes)
    {
        token.ThrowIfCancellationRequested(); budget?.Check();
        if (input.Length < 64) return null;
        uint footerSize = BoundedPeImage.U32(BoundedPeImage.ReadAt(input, input.Length - 4, 4), 0);
        bool hint = footerSize is 40 or 104;
        VPetFamilyEvidence evidence = new() { SourceSha256 = sourceHash };
        byte[]? decoded = null;
        VPetFamilyResult Failure(VPetFamilyStatus status, string code)
        {
            if (decoded is not null) CryptographicOperations.ZeroMemory(decoded);
            evidence.Status = status; evidence.ReasonCode = code; evidence.EnvelopeValidated = false;
            evidence.DerivedSha256 = null; evidence.DerivedLength = 0;
            return new(evidence);
        }
        try
        {
            BoundedPeImage pe = BoundedPeImage.Read(input, token, budget);
            if (pe.ClrRva != 0) return VPetWrapperInspector.Inspect(input, sourceHash, token, budget);
            if (!pe.NativeX64Dll) return null;
            PeDataSection code = pe.Section(".text");
            if (code.Length is <= 0 or > 1024 * 1024 || input.Length > Math.Min(MaximumInputBytes, maximumBytes))
                return hint ? Failure(VPetFamilyStatus.LimitReached, "VPET-FAMILY-SIZE-LIMIT") : null;
            using (BoundedReadOnlyStream codeStream = new(input, code.Offset, code.Length))
                evidence.CodeSha256 = Convert.ToHexString(await SHA256.HashDataAsync(codeStream, token));
            bool codeMatch = CodeIdentities.TryGetValue(evidence.CodeSha256, out VPetComponentRole codeRole);
            evidence.Role = codeRole;
            if (codeMatch) evidence.Signals.Add("VPET-KNOWN-CODE-SECTION");
            if (!hint && !codeMatch) return null;
            if (pe.RawEnd == input.Length && codeMatch)
            {
                evidence.Status = VPetFamilyStatus.CodeMatched; evidence.ReasonCode = "VPET-NATIVE-CODE-ONLY";
                return new(evidence);
            }
            if (!hint || input.Length - pe.RawEnd != footerSize + 4L)
                return Failure(VPetFamilyStatus.Malformed, "VPET-FOOTER-BOUNDS");
            evidence.FooterOffset = pe.RawEnd; evidence.FooterLength = footerSize + 4L;
            byte[] footer = BoundedPeImage.ReadAt(input, pe.RawEnd, checked((int)footerSize));
            if (footerSize == 40)
            {
                if (!codeMatch || codeRole != VPetComponentRole.Loader) return null;
                evidence.ExportModule = pe.OrdinalOneModule(input);
                if (evidence.ExportModule != "boot_plain.dll") return Failure(VPetFamilyStatus.Unsupported, "VPET-LOADER-EXPORT");
                foreach (int offset in new[] { 8, 24 }) evidence.RelatedNames.Add(LeafName(footer.AsSpan(offset, 16)));
                if (evidence.RelatedNames.Distinct(StringComparer.OrdinalIgnoreCase).Count() != 2)
                    return Failure(VPetFamilyStatus.Malformed, "VPET-LOADER-NAMES");
                evidence.Status = VPetFamilyStatus.CodeMatched; evidence.ReasonCode = "VPET-LOADER-STRUCTURE";
                evidence.Signals.Add("VPET-ORDINAL-ONE");
                evidence.EnvelopeValidated = true; return new(evidence);
            }
            if (codeRole == VPetComponentRole.Loader) return Failure(VPetFamilyStatus.Unsupported, "VPET-ENVELOPE-ROLE");
            long transformed = 0;
            for (int i = 0; i < 2; i++)
            {
                long rva = BoundedPeImage.U32(footer, 88 + i * 8), length = BoundedPeImage.U32(footer, 92 + i * 8);
                PeDataSection section = pe.Section(i == 0 ? ".rdata" : ".data");
                if (rva != section.Rva || length != section.Length || length <= 0 || (section.Characteristics & 0x20000000) != 0)
                    return Failure(VPetFamilyStatus.Malformed, "VPET-DECODE-REGION");
                long offset = pe.Map(rva, length);
                if (offset + length > pe.RawEnd) return Failure(VPetFamilyStatus.Malformed, "VPET-DECODE-BOUNDS");
                transformed += length;
                evidence.Regions.Add(new(rva, offset, length));
            }
            if (transformed > MaximumTransformedBytes) return Failure(VPetFamilyStatus.LimitReached, "VPET-DECODE-LIMIT");
            if (budget is not null && (pe.RawEnd > budget.RemainingWorkBytes / 2 || pe.RawEnd > budget.Limits.MaximumExpandedBytes - budget.AcceptedExpandedBytes))
                return Failure(VPetFamilyStatus.LimitReached, "VPET-DECODE-BUDGET");
            token.ThrowIfCancellationRequested();
            decoded = BoundedPeImage.ReadAt(input, 0, checked((int)pe.RawEnd));
            Transform(decoded, footer, evidence.Regions, token, budget);
            budget?.ChargeDecoded(decoded.Length);
            using MemoryStream reconstructed = new(decoded, writable: false);
            evidence.ExportModule = pe.OrdinalOneModule(reconstructed);
            VPetComponentRole role = evidence.ExportModule switch
            {
                "_1.bin" => VPetComponentRole.UiPayload,
                "_2.bin" => VPetComponentRole.CredentialPayload,
                _ => VPetComponentRole.Unknown
            };
            if (role == VPetComponentRole.Unknown || codeMatch && codeRole != role)
                return Failure(VPetFamilyStatus.Unsupported, "VPET-DECODE-EXPORT");
            evidence.Role = role;
            evidence.DerivedSha256 = Convert.ToHexString(SHA256.HashData(decoded)); evidence.DerivedLength = decoded.Length;
            evidence.Status = VPetFamilyStatus.Decoded; evidence.ReasonCode = "VPET-DATA-DECODED";
            evidence.EnvelopeValidated = true; evidence.Signals.Add("VPET-ORDINAL-ONE");
            budget?.AcceptExpansion(decoded.Length);
            return new(evidence, decoded);
        }
        catch (InvalidDataException)
        {
            if (!hint && evidence.Role == VPetComponentRole.Unknown) return null;
            return Failure(VPetFamilyStatus.Malformed, "VPET-PE-INVALID");
        }
        catch
        {
            if (decoded is not null) CryptographicOperations.ZeroMemory(decoded);
            throw;
        }
    }

    private static string LeafName(ReadOnlySpan<byte> bytes)
    {
        int zero = bytes.IndexOf((byte)0);
        if (zero is < 1 or > 15 || bytes[zero..].ContainsAnyExcept((byte)0)) throw new InvalidDataException("VPET-LOADER-NAMES");
        string name = Encoding.ASCII.GetString(bytes[..zero]);
        if (!name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
            name.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-')) || name.StartsWith('.'))
            throw new InvalidDataException("VPET-LOADER-NAMES");
        return name;
    }

    private static void Transform(byte[] bytes, byte[] footer, IReadOnlyList<VPetDecodedRegion> regions,
        CancellationToken token, ContainerResourceBudget? budget)
    {
        byte[] seedInput = new byte[80], counterInput = new byte[36], block = new byte[32];
        try
        {
            for (int i = 0; i < 32; i++) seedInput[i] = (byte)(footer[8 + i] ^ footer[40 + i]);
            footer.AsSpan(40, 48).CopyTo(seedInput.AsSpan(32));
            SHA256.HashData(seedInput, counterInput.AsSpan(0, 32));
            uint counter = 0; int position = 32;
            foreach (VPetDecodedRegion region in regions)
            {
                for (long i = 0; i < region.Length; i++)
                {
                    if (position == 32)
                    {
                        if ((counter & 255) == 0) { token.ThrowIfCancellationRequested(); budget?.Check(); }
                        BinaryPrimitives.WriteUInt32LittleEndian(counterInput.AsSpan(32), counter++);
                        SHA256.HashData(counterInput, block); position = 0;
                    }
                    bytes[checked((int)(region.Offset + i))] ^= block[position++];
                }
            }
            token.ThrowIfCancellationRequested();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seedInput); CryptographicOperations.ZeroMemory(counterInput);
            CryptographicOperations.ZeroMemory(block);
        }
    }
}

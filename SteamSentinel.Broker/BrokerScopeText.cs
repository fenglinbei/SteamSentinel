using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Broker;

internal enum BrokerFileValidationStage { Prepare, Execute, FinalQuarantine, Restore }

internal static class BrokerScopeText
{
    internal static MessageText IdentityChanged => MessageText.Create("Scope.IdentityChanged");
    internal static MessageText InvalidIdentity => MessageText.Create("Scope.InvalidIdentity");
    internal static MessageText NotAuthorized => MessageText.Create("Scope.NotAuthorized");
    internal static MessageText HardLinks => MessageText.Create("Scope.HardLinks");
    internal static MessageText UnsupportedMetadata => MessageText.Create("Scope.UnsupportedMetadata");
    internal static MessageText MetadataUnavailable => MessageText.Create("Scope.MetadataUnavailable");
    internal static MessageText RestoreMetadataInvalid => MessageText.Create("Scope.RestoreMetadataInvalid");
    internal static MessageText ProtectedPath => MessageText.Create("Scope.ProtectedPath");

    // Keep these descriptors flat. The action loop wraps them in an exception, then
    // occupancy and error messages; another nested label would exceed the display depth.
    internal static MessageText IdentityDifference(BrokerFileValidationStage stage, string field,
        string expected, string actual) => MessageText.Create($"Scope.Diagnostic.{stage}.{field}",
            DiagnosticValue(expected), DiagnosticValue(actual));

    internal static MessageText MetadataDifference(BrokerFileValidationStage stage,
        BrokerFileMetadata expected, BrokerFileMetadata actual) => MessageText.Create($"Scope.Diagnostic.{stage}.Metadata",
            Difference(SecurityFingerprint(expected.SecurityDescriptor), SecurityFingerprint(actual.SecurityDescriptor)),
            Difference($"0x{expected.Attributes:X8}", $"0x{actual.Attributes:X8}"),
            Difference(expected.CreationTimeUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                actual.CreationTimeUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)),
            Difference(expected.LastWriteTimeUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
                actual.LastWriteTimeUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)));

    private static string Difference(string expected, string actual) =>
        expected.Equals(actual, StringComparison.Ordinal) ? "=" : $"{expected} → {actual}";

    private static string SecurityFingerprint(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    // The result already carries the complete requested target. Bound unusual path
    // differences without losing their full-value fingerprint or the bilingual message.
    private static string DiagnosticValue(string value) => value.Length <= 192 ? value :
        $"{value[..80]}…{value[^24..]} [SHA-256:{SecurityFingerprint(value)}]";

    internal static UnauthorizedAccessException Denied(MessageText message) =>
        MessageExceptions.Create(message, text => new UnauthorizedAccessException(text));
    internal static InvalidDataException Invalid(MessageText message, Exception? inner = null) =>
        MessageExceptions.Create(message, text => new InvalidDataException(text, inner));
    internal static IOException Io(MessageText message) =>
        MessageExceptions.Create(message, text => new IOException(text));
    internal static Win32Exception Native(int error, MessageText message) => MessageExceptions.Win32(error, message);
}

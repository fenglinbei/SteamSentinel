using System.ComponentModel;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.Broker;

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

    internal static UnauthorizedAccessException Denied(MessageText message) =>
        MessageExceptions.Create(message, text => new UnauthorizedAccessException(text));
    internal static InvalidDataException Invalid(MessageText message, Exception? inner = null) =>
        MessageExceptions.Create(message, text => new InvalidDataException(text, inner));
    internal static IOException Io(MessageText message) =>
        MessageExceptions.Create(message, text => new IOException(text));
    internal static Win32Exception Native(int error, MessageText message) => MessageExceptions.Win32(error, message);
}

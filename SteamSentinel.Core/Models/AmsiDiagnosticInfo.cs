namespace SteamSentinel.Core.Models;

public enum AmsiOperation { Initialize, OpenSession, ScanBuffer, Input, Disposed }

/// <summary>Stable diagnostic evidence; display language never changes the engine verdict.</summary>
public sealed record AmsiDiagnosticInfo(string Code, AmsiOperation Operation, int? HResult,
    int? InitializeHResult, int? OpenSessionHResult, string Architecture, string Integrity);

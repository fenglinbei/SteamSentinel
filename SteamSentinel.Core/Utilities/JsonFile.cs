using SteamSentinel.Core.Reporting;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SteamSentinel.Core.Utilities;

public static class JsonFile
{
    public static JsonSerializerOptions Options { get; } = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static async Task<T> ReadAsync<T>(string path, CancellationToken cancellationToken = default)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return await ReadAsync<T>(stream, path, cancellationToken).ConfigureAwait(false);
    }

    public static async Task<T> ReadAsync<T>(
        Stream stream,
        string? sourceDescription = null,
        CancellationToken cancellationToken = default) =>
        await ReadAsync<T>(stream, sourceDescription is null ? MessageText.Create("Backend.Core.JsonFile.ReadAsync.01") : (MessageText)sourceDescription,
            cancellationToken).ConfigureAwait(false);

    public static async Task<T> ReadAsync<T>(
        Stream stream,
        MessageText sourceDescription,
        CancellationToken cancellationToken = default)
    {
        return await JsonSerializer.DeserializeAsync<T>(stream, Options, cancellationToken).ConfigureAwait(false)
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.JsonFile.ReadAsync.02", (sourceDescription)), sourceText => new InvalidDataException(sourceText));
    }

    public static async Task WriteAtomicAsync<T>(string path, T value, CancellationToken cancellationToken = default,
        JsonSerializerOptions? options = null)
    {
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.JsonFile.WriteAtomicAsync.01"), sourceText => new InvalidOperationException(sourceText));
        Directory.CreateDirectory(directory);

        string temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            await using (FileStream stream = new(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await JsonSerializer.SerializeAsync(stream, value, options ?? Options, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(temporary, fullPath, true);
        }
        finally
        {
            if (File.Exists(temporary))
            {
                File.Delete(temporary);
            }
        }
    }

    public static async Task WriteNewAsync<T>(string path, T value, CancellationToken cancellationToken = default)
    {
        string fullPath = Path.GetFullPath(path);
        string directory = Path.GetDirectoryName(fullPath)
            ?? throw MessageExceptions.Create(MessageText.Create("Backend.Core.JsonFile.WriteNewAsync.01"), sourceText => new InvalidOperationException(sourceText));
        Directory.CreateDirectory(directory);

        await using FileStream stream = new(
            fullPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 64 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await JsonSerializer.SerializeAsync(stream, value, Options, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        stream.Flush(flushToDisk: true);
    }
}

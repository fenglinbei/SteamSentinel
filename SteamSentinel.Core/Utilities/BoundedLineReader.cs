using System.Text;

namespace SteamSentinel.Core.Utilities;

/// <summary>Bounds a frame before allocating its complete string, including when no newline arrives.</summary>
public sealed class BoundedLineReader(TextReader reader, int maximumCharacters = 1024 * 1024)
{
    private readonly char[] _buffer = new char[8192];
    private int _position, _count;
    public async Task<string?> ReadLineAsync(CancellationToken token = default)
    {
        StringBuilder line = new();
        while (true)
        {
            if (_position == _count)
            {
                _count = await reader.ReadAsync(_buffer.AsMemory(), token).ConfigureAwait(false);
                _position = 0;
                if (_count == 0) return line.Length == 0 ? null : line.ToString().TrimEnd('\r');
            }
            int end = Array.IndexOf(_buffer, '\n', _position, _count - _position);
            int length = (end < 0 ? _count : end) - _position;
            if (line.Length + length > maximumCharacters) throw new InvalidDataException("扫描通信数据超过单批安全上限。");
            line.Append(_buffer, _position, length);
            _position += length;
            if (end >= 0) { _position++; return line.ToString().TrimEnd('\r'); }
        }
    }
}

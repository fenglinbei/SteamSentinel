using System.Windows.Markup;
using SteamSentinel.Core.Reporting;

namespace SteamSentinel.App.Localization;

/// <summary>Resolves display text when a view is created. Never participates in decisions.</summary>
[MarkupExtensionReturnType(typeof(string))]
public sealed class TextExtension(string key) : MarkupExtension
{
    public string Key { get; } = key;
    public override object ProvideValue(IServiceProvider serviceProvider) => DisplayText.Get(Key);
}
